//! Compilation to a small register machine.
//!
//! Each expression writes a register. Instructions can load constants and names,
//! move/store values, build lists, apply unary/binary operators, jump, dispatch
//! commands, expand globs, drive iterators, and return. Definitions, aliases, and
//! includes are runtime instructions because they must persist in the interpreter.

use alloc::{boxed::Box, string::String, vec::Vec};

use crate::{
    ast::{BinaryOp, Expr, ExprNode, Location, Statement, StatementKind},
    Error, Value, MAX_INSTRUCTIONS,
};

pub(crate) type Register = usize;

#[derive(Clone, Debug)]
pub(crate) struct Chunk {
    pub source_name: String,
    pub register_count: usize,
    pub instructions: Vec<LocatedInstruction>,
}

#[derive(Clone, Debug)]
pub(crate) struct LocatedInstruction {
    pub location: Location,
    pub instruction: Instruction,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum UnaryOp {
    Not,
}

#[derive(Clone, Debug)]
pub(crate) struct CallArgument {
    pub register: Register,
    pub splice: bool,
}

#[derive(Clone, Debug)]
pub(crate) enum Instruction {
    Constant {
        dst: Register,
        value: Value,
    },
    Move {
        dst: Register,
        src: Register,
    },
    LoadGlobal {
        dst: Register,
        name: String,
    },
    StoreGlobal {
        name: String,
        src: Register,
    },
    BuildList {
        dst: Register,
        values: Vec<Register>,
    },
    Unary {
        dst: Register,
        op: UnaryOp,
        src: Register,
    },
    Binary {
        dst: Register,
        op: BinaryOp,
        left: Register,
        right: Register,
    },
    Jump {
        target: usize,
    },
    JumpIfFalse {
        condition: Register,
        target: usize,
    },
    JumpIfTrue {
        condition: Register,
        target: usize,
    },
    Call {
        dst: Register,
        name: String,
        arguments: Vec<CallArgument>,
    },
    Glob {
        dst: Register,
        pattern: String,
    },
    IterInit {
        iterator: Register,
        value: Register,
    },
    IterNext {
        iterator: Register,
        dst: Register,
        end: usize,
    },
    DefineFunction {
        name: String,
        parameters: Vec<String>,
        body: Box<Chunk>,
    },
    DefineAlias {
        name: String,
        target: String,
    },
    Include {
        dst: Register,
        path: String,
    },
    Run {
        dst: Register,
        path: String,
    },
    Return {
        src: Register,
    },
}

pub(crate) fn compile(statements: &[Statement], source_name: &str) -> Result<Chunk, Error> {
    let mut compiler = Compiler {
        source_name,
        instructions: Vec::new(),
        next_register: 0,
    };
    let result = compiler.compile_statements(statements)?;
    let location = statements
        .last()
        .map(|s| s.location)
        .unwrap_or(Location { line: 1, column: 1 });
    compiler.emit(location, Instruction::Return { src: result })?;
    Ok(Chunk {
        source_name: source_name.into(),
        register_count: compiler.next_register,
        instructions: compiler.instructions,
    })
}

struct Compiler<'a> {
    source_name: &'a str,
    instructions: Vec<LocatedInstruction>,
    next_register: usize,
}

impl Compiler<'_> {
    fn register(&mut self) -> Register {
        let register = self.next_register;
        self.next_register += 1;
        register
    }

    fn emit(&mut self, location: Location, instruction: Instruction) -> Result<usize, Error> {
        if self.instructions.len() >= MAX_INSTRUCTIONS {
            return Err(Error::at(
                self.source_name,
                location.line,
                location.column,
                "compiled instruction limit exceeded",
            ));
        }
        let index = self.instructions.len();
        self.instructions.push(LocatedInstruction {
            location,
            instruction,
        });
        Ok(index)
    }

    fn patch_target(&mut self, index: usize, target: usize) {
        match &mut self.instructions[index].instruction {
            Instruction::Jump { target: value }
            | Instruction::JumpIfFalse { target: value, .. }
            | Instruction::JumpIfTrue { target: value, .. } => *value = target,
            Instruction::IterNext { end, .. } => *end = target,
            _ => unreachable!(),
        }
    }

    fn unit(&mut self, location: Location) -> Result<Register, Error> {
        let dst = self.register();
        self.emit(
            location,
            Instruction::Constant {
                dst,
                value: Value::Unit,
            },
        )?;
        Ok(dst)
    }

    fn compile_statements(&mut self, statements: &[Statement]) -> Result<Register, Error> {
        let mut result = self.unit(
            statements
                .first()
                .map(|s| s.location)
                .unwrap_or(Location { line: 1, column: 1 }),
        )?;
        for statement in statements {
            result = self.compile_statement(statement)?;
        }
        Ok(result)
    }

    fn compile_statement(&mut self, statement: &Statement) -> Result<Register, Error> {
        let location = statement.location;
        match &statement.value {
            StatementKind::Assignment(name, expression) => {
                let value = self.compile_expr(expression)?;
                self.emit(
                    location,
                    Instruction::StoreGlobal {
                        name: name.clone(),
                        src: value,
                    },
                )?;
                Ok(value)
            }
            StatementKind::Expression(expression) => self.compile_expr(expression),
            StatementKind::Command(name, arguments) => {
                let mut compiled = Vec::new();
                for argument in arguments {
                    compiled.push(CallArgument {
                        register: self.compile_expr(argument)?,
                        splice: matches!(argument.value, Expr::Glob(_)),
                    });
                }
                let dst = self.register();
                self.emit(
                    location,
                    Instruction::Call {
                        dst,
                        name: name.clone(),
                        arguments: compiled,
                    },
                )?;
                Ok(dst)
            }
            StatementKind::Include(path) | StatementKind::Run(path) => {
                let dst = self.register();
                let instruction = if matches!(&statement.value, StatementKind::Run(_)) {
                    Instruction::Run {
                        dst,
                        path: path.clone(),
                    }
                } else {
                    Instruction::Include {
                        dst,
                        path: path.clone(),
                    }
                };
                self.emit(location, instruction)?;
                Ok(dst)
            }
            StatementKind::Alias(name, target) => {
                self.emit(
                    location,
                    Instruction::DefineAlias {
                        name: name.clone(),
                        target: target.clone(),
                    },
                )?;
                self.unit(location)
            }
            StatementKind::Definition {
                name,
                parameters,
                body,
            } => {
                let body = compile(body, self.source_name)?;
                self.emit(
                    location,
                    Instruction::DefineFunction {
                        name: name.clone(),
                        parameters: parameters.clone(),
                        body: Box::new(body),
                    },
                )?;
                self.unit(location)
            }
            StatementKind::For {
                variable,
                iterable,
                body,
            } => {
                let value = self.compile_expr(iterable)?;
                let iterator = self.register();
                self.emit(location, Instruction::IterInit { iterator, value })?;
                let start = self.instructions.len();
                let item = self.register();
                let next = self.emit(
                    location,
                    Instruction::IterNext {
                        iterator,
                        dst: item,
                        end: 0,
                    },
                )?;
                self.emit(
                    location,
                    Instruction::StoreGlobal {
                        name: variable.clone(),
                        src: item,
                    },
                )?;
                self.compile_statements(body)?;
                self.emit(location, Instruction::Jump { target: start })?;
                let end = self.instructions.len();
                self.patch_target(next, end);
                self.unit(location)
            }
            StatementKind::Repeat { count, body } => {
                let value = self.compile_expr(count)?;
                let iterator = self.register();
                self.emit(location, Instruction::IterInit { iterator, value })?;
                let start = self.instructions.len();
                let ignored = self.register();
                let next = self.emit(
                    location,
                    Instruction::IterNext {
                        iterator,
                        dst: ignored,
                        end: 0,
                    },
                )?;
                self.compile_statements(body)?;
                self.emit(location, Instruction::Jump { target: start })?;
                let end = self.instructions.len();
                self.patch_target(next, end);
                self.unit(location)
            }
            StatementKind::While { condition, body } | StatementKind::Until { condition, body } => {
                let until = matches!(&statement.value, StatementKind::Until { .. });
                let start = self.instructions.len();
                let condition = self.compile_expr(condition)?;
                let jump = if until {
                    self.emit(
                        location,
                        Instruction::JumpIfTrue {
                            condition,
                            target: 0,
                        },
                    )?
                } else {
                    self.emit(
                        location,
                        Instruction::JumpIfFalse {
                            condition,
                            target: 0,
                        },
                    )?
                };
                self.compile_statements(body)?;
                self.emit(location, Instruction::Jump { target: start })?;
                let end = self.instructions.len();
                self.patch_target(jump, end);
                self.unit(location)
            }
            StatementKind::DoWhile { body, condition } => {
                let start = self.instructions.len();
                self.compile_statements(body)?;
                let condition = self.compile_expr(condition)?;
                self.emit(
                    location,
                    Instruction::JumpIfTrue {
                        condition,
                        target: start,
                    },
                )?;
                self.unit(location)
            }
            StatementKind::Return(expression) => {
                let value = match expression {
                    Some(expression) => self.compile_expr(expression)?,
                    None => self.unit(location)?,
                };
                self.emit(location, Instruction::Return { src: value })?;
                Ok(value)
            }
        }
    }

    fn compile_expr(&mut self, expression: &ExprNode) -> Result<Register, Error> {
        let location = expression.location;
        match &expression.value {
            Expr::Value(value) => {
                let dst = self.register();
                self.emit(
                    location,
                    Instruction::Constant {
                        dst,
                        value: value.clone(),
                    },
                )?;
                Ok(dst)
            }
            Expr::Variable(name) => {
                let dst = self.register();
                self.emit(
                    location,
                    Instruction::LoadGlobal {
                        dst,
                        name: name.clone(),
                    },
                )?;
                Ok(dst)
            }
            Expr::List(values) => {
                let mut registers = Vec::new();
                for value in values {
                    registers.push(self.compile_expr(value)?);
                }
                let dst = self.register();
                self.emit(
                    location,
                    Instruction::BuildList {
                        dst,
                        values: registers,
                    },
                )?;
                Ok(dst)
            }
            Expr::Glob(pattern) => {
                let dst = self.register();
                self.emit(
                    location,
                    Instruction::Glob {
                        dst,
                        pattern: pattern.clone(),
                    },
                )?;
                Ok(dst)
            }
            Expr::UnaryNot(value) => {
                let src = self.compile_expr(value)?;
                let dst = self.register();
                self.emit(
                    location,
                    Instruction::Unary {
                        dst,
                        op: UnaryOp::Not,
                        src,
                    },
                )?;
                Ok(dst)
            }
            Expr::Binary {
                op: BinaryOp::And,
                left,
                right,
            } => self.compile_short_circuit(left, right, false),
            Expr::Binary {
                op: BinaryOp::Or,
                left,
                right,
            } => self.compile_short_circuit(left, right, true),
            Expr::Binary { op, left, right } => {
                let left = self.compile_expr(left)?;
                let right = self.compile_expr(right)?;
                let dst = self.register();
                self.emit(
                    location,
                    Instruction::Binary {
                        dst,
                        op: *op,
                        left,
                        right,
                    },
                )?;
                Ok(dst)
            }
        }
    }

    fn compile_short_circuit(
        &mut self,
        left: &ExprNode,
        right: &ExprNode,
        is_or: bool,
    ) -> Result<Register, Error> {
        let location = left.location;
        let left = self.compile_expr(left)?;
        let dst = self.register();
        self.emit(
            location,
            Instruction::Constant {
                dst,
                value: Value::Boolean(is_or),
            },
        )?;
        let jump = if is_or {
            self.emit(
                location,
                Instruction::JumpIfTrue {
                    condition: left,
                    target: 0,
                },
            )?
        } else {
            self.emit(
                location,
                Instruction::JumpIfFalse {
                    condition: left,
                    target: 0,
                },
            )?
        };
        let right = self.compile_expr(right)?;
        let inverted = self.register();
        self.emit(
            location,
            Instruction::Unary {
                dst: inverted,
                op: UnaryOp::Not,
                src: right,
            },
        )?;
        let normalized = self.register();
        self.emit(
            location,
            Instruction::Unary {
                dst: normalized,
                op: UnaryOp::Not,
                src: inverted,
            },
        )?;
        self.emit(
            location,
            Instruction::Move {
                dst,
                src: normalized,
            },
        )?;
        let end = self.instructions.len();
        self.patch_target(jump, end);
        Ok(dst)
    }
}
