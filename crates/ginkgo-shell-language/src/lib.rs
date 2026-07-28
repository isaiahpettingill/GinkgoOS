#![no_std]

//! Parser, bytecode compiler, and interpreter for the GinkgoOS shell language.

extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::{cmp::Ordering, fmt};

mod ast;
mod bytecode;
mod parser;

use ast::{BinaryOp, Location};
use bytecode::{Chunk, Instruction, UnaryOp};

pub type Integer = i64;
pub type List = Vec<Value>;
pub type Map = BTreeMap<String, Value>;

pub(crate) const MAX_INSTRUCTIONS: usize = 100_000;
const MAX_CALL_DEPTH: usize = 32;
const MAX_LIST_VALUES: usize = 4_096;
const MAX_TEXT_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Unit,
    Boolean(bool),
    Integer(Integer),
    String(String),
    List(List),
    Map(Map),
}

impl Value {
    pub fn is_unit(&self) -> bool {
        matches!(self, Self::Unit)
    }

    pub fn is_truthy(&self) -> bool {
        match self {
            Self::Unit => false,
            Self::Boolean(value) => *value,
            Self::Integer(value) => *value != 0,
            Self::String(value) => !value.is_empty(),
            Self::List(value) => !value.is_empty(),
            Self::Map(value) => !value.is_empty(),
        }
    }

    pub fn as_string(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_integer(&self) -> Option<Integer> {
        match self {
            Self::Integer(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Boolean(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&List> {
        match self {
            Self::List(value) => Some(value),
            _ => None,
        }
    }
}

impl From<()> for Value {
    fn from(_: ()) -> Self {
        Self::Unit
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Boolean(value)
    }
}

impl From<Integer> for Value {
    fn from(value: Integer) -> Self {
        Self::Integer(value)
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Self::String(value.into())
    }
}

impl From<List> for Value {
    fn from(value: List) -> Self {
        Self::List(value)
    }
}

impl From<Map> for Value {
    fn from(value: Map) -> Self {
        Self::Map(value)
    }
}

impl fmt::Display for Value {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unit => formatter.write_str("()"),
            Self::Boolean(value) => write!(formatter, "{value}"),
            Self::Integer(value) => write!(formatter, "{value}"),
            Self::String(value) => formatter.write_str(value),
            Self::List(values) => {
                formatter.write_str("@[")?;
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        formatter.write_str(", ")?;
                    }
                    write!(formatter, "{value}")?;
                }
                formatter.write_str("]")
            }
            Self::Map(values) => {
                formatter.write_str("{")?;
                for (index, (key, value)) in values.iter().enumerate() {
                    if index != 0 {
                        formatter.write_str(", ")?;
                    }
                    write!(formatter, "{key}: {value}")?;
                }
                formatter.write_str("}")
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallMode {
    Auto,
    Application,
    Builtin,
    AbsolutePath,
}

pub trait Host {
    fn call(&mut self, mode: CallMode, name: &str, args: List) -> Result<Value, String>;
    fn include(&mut self, path: &str) -> Result<String, String>;
    fn glob(&mut self, pattern: &str) -> Result<Vec<String>, String>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    source_name: String,
    line: usize,
    column: usize,
    message: String,
}

impl Error {
    fn at(source_name: &str, line: usize, column: usize, message: impl Into<String>) -> Self {
        Self {
            source_name: source_name.into(),
            line,
            column,
            message: message.into(),
        }
    }

    pub fn source_name(&self) -> &str {
        &self.source_name
    }
    pub fn line(&self) -> usize {
        self.line
    }
    pub fn column(&self) -> usize {
        self.column
    }
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}:{}: {}",
            self.source_name, self.line, self.column, self.message
        )
    }
}

#[derive(Clone, Debug)]
struct UserFunction {
    parameters: Vec<String>,
    body: Chunk,
}

/// A persistent shell interpreter. Source is parsed into an AST, compiled to
/// register-machine bytecode, and only then executed.
pub struct Interpreter {
    globals: Map,
    functions: BTreeMap<String, UserFunction>,
    aliases: BTreeMap<String, String>,
    included_paths: BTreeSet<String>,
    active_scripts: Vec<String>,
}

impl Interpreter {
    pub fn new() -> Self {
        Self {
            globals: BTreeMap::new(),
            functions: BTreeMap::new(),
            aliases: BTreeMap::new(),
            included_paths: BTreeSet::new(),
            active_scripts: Vec::new(),
        }
    }

    pub fn eval(
        &mut self,
        source: &str,
        source_name: &str,
        host: &mut impl Host,
    ) -> Result<Value, Error> {
        if source.len() > MAX_TEXT_BYTES {
            return Err(Error::at(
                source_name,
                1,
                1,
                "source exceeds the 64 KiB limit",
            ));
        }
        let statements = parser::parse(source, source_name)?;
        let chunk = bytecode::compile(&statements, source_name)?;
        let mut execution = Execution {
            instructions: 0,
            call_depth: 0,
        };
        self.execute(&chunk, BTreeMap::new(), host, &mut execution)
    }

    fn execute<H: Host>(
        &mut self,
        chunk: &Chunk,
        locals: Map,
        host: &mut H,
        execution: &mut Execution,
    ) -> Result<Value, Error> {
        let mut registers = vec![Value::Unit; chunk.register_count];
        let mut iterators: BTreeMap<usize, IteratorState> = BTreeMap::new();
        let mut pc = 0;
        while pc < chunk.instructions.len() {
            execution.instructions += 1;
            let located = &chunk.instructions[pc];
            if execution.instructions > MAX_INSTRUCTIONS {
                return Err(runtime_error(
                    chunk,
                    located.location,
                    "execution instruction limit exceeded",
                ));
            }
            pc += 1;
            match &located.instruction {
                Instruction::Constant { dst, value } => registers[*dst] = value.clone(),
                Instruction::Move { dst, src } => registers[*dst] = registers[*src].clone(),
                Instruction::LoadGlobal { dst, name } => {
                    registers[*dst] = locals
                        .get(name)
                        .or_else(|| self.globals.get(name))
                        .cloned()
                        .ok_or_else(|| {
                            runtime_error(
                                chunk,
                                located.location,
                                format!("unknown variable `${name}`"),
                            )
                        })?;
                }
                Instruction::StoreGlobal { name, src } => {
                    self.globals.insert(name.clone(), registers[*src].clone());
                }
                Instruction::BuildList { dst, values } => {
                    if values.len() > MAX_LIST_VALUES {
                        return Err(runtime_error(
                            chunk,
                            located.location,
                            "list exceeds 4096 values",
                        ));
                    }
                    registers[*dst] = Value::List(
                        values
                            .iter()
                            .map(|value| registers[*value].clone())
                            .collect(),
                    );
                }
                Instruction::Unary {
                    dst,
                    op: UnaryOp::Not,
                    src,
                } => {
                    registers[*dst] = Value::Boolean(!registers[*src].is_truthy());
                }
                Instruction::Binary {
                    dst,
                    op,
                    left,
                    right,
                } => {
                    registers[*dst] = apply_binary(*op, &registers[*left], &registers[*right])
                        .map_err(|message| runtime_error(chunk, located.location, message))?;
                }
                Instruction::Jump { target } => {
                    pc = *target;
                }
                Instruction::JumpIfFalse { condition, target } => {
                    if !registers[*condition].is_truthy() {
                        pc = *target;
                    }
                }
                Instruction::JumpIfTrue { condition, target } => {
                    if registers[*condition].is_truthy() {
                        pc = *target;
                    }
                }
                Instruction::Glob { dst, pattern } => {
                    let matches = host
                        .glob(pattern)
                        .map_err(|message| runtime_error(chunk, located.location, message))?;
                    if matches.len() > MAX_LIST_VALUES {
                        return Err(runtime_error(
                            chunk,
                            located.location,
                            "glob exceeds 4096 matches",
                        ));
                    }
                    for value in &matches {
                        check_text(value, chunk, located.location, "glob match")?;
                    }
                    registers[*dst] = Value::List(matches.into_iter().map(Value::String).collect());
                }
                Instruction::Call {
                    dst,
                    name,
                    arguments,
                } => {
                    let mut args = Vec::new();
                    for argument in arguments {
                        let value = registers[argument.register].clone();
                        if argument.splice {
                            match value {
                                Value::List(values) => args.extend(values),
                                _ => {
                                    return Err(runtime_error(
                                        chunk,
                                        located.location,
                                        "only a list can be spliced into command arguments",
                                    ))
                                }
                            }
                        } else {
                            args.push(value);
                        }
                        if args.len() > MAX_LIST_VALUES {
                            return Err(runtime_error(
                                chunk,
                                located.location,
                                "command arguments exceed 4096 values",
                            ));
                        }
                    }
                    registers[*dst] =
                        self.dispatch(name, args, host, execution, chunk, located.location)?;
                }
                Instruction::IterInit { iterator, value } => {
                    let values = match &registers[*value] {
                        Value::List(values) => values.clone(),
                        Value::Integer(count)
                            if *count >= 0 && (*count as usize) <= MAX_LIST_VALUES =>
                        {
                            (0..*count).map(Value::Integer).collect()
                        }
                        Value::Integer(_) => {
                            return Err(runtime_error(
                                chunk,
                                located.location,
                                "repeat count must be between 0 and 4096",
                            ))
                        }
                        _ => {
                            return Err(runtime_error(
                                chunk,
                                located.location,
                                "iteration requires a list or non-negative integer",
                            ))
                        }
                    };
                    iterators.insert(*iterator, IteratorState { values, index: 0 });
                }
                Instruction::IterNext { iterator, dst, end } => {
                    let state = iterators
                        .get_mut(iterator)
                        .expect("iterator was initialized");
                    if state.index == state.values.len() {
                        pc = *end;
                    } else {
                        registers[*dst] = state.values[state.index].clone();
                        state.index += 1;
                    }
                }
                Instruction::DefineFunction {
                    name,
                    parameters,
                    body,
                } => {
                    self.functions.insert(
                        name.clone(),
                        UserFunction {
                            parameters: parameters.clone(),
                            body: (**body).clone(),
                        },
                    );
                }
                Instruction::DefineAlias { name, target } => {
                    let previous = self.aliases.insert(name.clone(), target.clone());
                    if self.resolve_alias(name).is_err() {
                        match previous {
                            Some(value) => {
                                self.aliases.insert(name.clone(), value);
                            }
                            None => {
                                self.aliases.remove(name);
                            }
                        }
                        return Err(runtime_error(
                            chunk,
                            located.location,
                            format!("alias `{name}` creates a cycle"),
                        ));
                    }
                }
                Instruction::Include { dst, path } => {
                    registers[*dst] = self.execute_script(
                        path,
                        true,
                        "include",
                        host,
                        execution,
                        chunk,
                        located.location,
                    )?;
                }
                Instruction::Run { dst, path } => {
                    registers[*dst] = self.execute_script(
                        path,
                        false,
                        "run",
                        host,
                        execution,
                        chunk,
                        located.location,
                    )?;
                }
                Instruction::Return { src } => return Ok(registers[*src].clone()),
            }
        }
        Ok(Value::Unit)
    }

    fn dispatch<H: Host>(
        &mut self,
        requested_name: &str,
        args: List,
        host: &mut H,
        execution: &mut Execution,
        caller: &Chunk,
        location: Location,
    ) -> Result<Value, Error> {
        let (mode, name) = classify_name(requested_name);
        if mode != CallMode::Auto {
            return host
                .call(mode, name, args)
                .map_err(|message| runtime_error(caller, location, message));
        }
        let resolved = self.resolve_alias(name).map_err(|_| {
            runtime_error(
                caller,
                location,
                format!("alias cycle while resolving `{name}`"),
            )
        })?;
        let (mode, name) = classify_name(&resolved);
        if mode == CallMode::Auto {
            if let Some(function) = self.functions.get(name).cloned() {
                if function.parameters.len() != args.len() {
                    return Err(runtime_error(
                        caller,
                        location,
                        format!(
                            "function `{name}` expects {} arguments, got {}",
                            function.parameters.len(),
                            args.len()
                        ),
                    ));
                }
                if execution.call_depth >= MAX_CALL_DEPTH {
                    return Err(runtime_error(caller, location, "call depth limit exceeded"));
                }
                let locals = function.parameters.into_iter().zip(args).collect();
                execution.call_depth += 1;
                let result = self.execute(&function.body, locals, host, execution);
                execution.call_depth -= 1;
                return result;
            }
        }
        host.call(mode, name, args)
            .map_err(|message| runtime_error(caller, location, message))
    }

    fn resolve_alias(&self, name: &str) -> Result<String, ()> {
        let mut current = name.to_string();
        let mut seen = BTreeSet::new();
        while classify_name(&current).0 == CallMode::Auto {
            if !seen.insert(current.clone()) {
                return Err(());
            }
            match self.aliases.get(&current) {
                Some(target) => current = target.clone(),
                None => break,
            }
        }
        Ok(current)
    }

    fn execute_script<H: Host>(
        &mut self,
        path: &str,
        once: bool,
        operation: &str,
        host: &mut H,
        execution: &mut Execution,
        caller: &Chunk,
        location: Location,
    ) -> Result<Value, Error> {
        if self.active_scripts.iter().any(|active| active == path) {
            return Err(runtime_error(
                caller,
                location,
                format!("{operation} cycle involving `{path}`"),
            ));
        }
        if once && self.included_paths.contains(path) {
            return Ok(Value::Unit);
        }
        let source = host
            .include(path)
            .map_err(|message| runtime_error(caller, location, message))?;
        if source.len() > MAX_TEXT_BYTES {
            return Err(runtime_error(
                caller,
                location,
                format!("{operation} `{path}` exceeds the 64 KiB limit"),
            ));
        }
        self.active_scripts.push(path.into());
        let result = parser::parse(&source, path)
            .and_then(|statements| bytecode::compile(&statements, path))
            .and_then(|chunk| self.execute(&chunk, BTreeMap::new(), host, execution));
        self.active_scripts.pop();
        if once && result.is_ok() {
            self.included_paths.insert(path.into());
        }
        result
    }
}

impl Default for Interpreter {
    fn default() -> Self {
        Self::new()
    }
}

struct Execution {
    instructions: usize,
    call_depth: usize,
}

struct IteratorState {
    values: List,
    index: usize,
}

fn runtime_error(chunk: &Chunk, location: Location, message: impl Into<String>) -> Error {
    Error::at(&chunk.source_name, location.line, location.column, message)
}

fn check_text(value: &str, chunk: &Chunk, location: Location, kind: &str) -> Result<(), Error> {
    if value.len() > MAX_TEXT_BYTES {
        Err(runtime_error(
            chunk,
            location,
            format!("{kind} exceeds the 64 KiB limit"),
        ))
    } else {
        Ok(())
    }
}

fn classify_name(name: &str) -> (CallMode, &str) {
    if let Some(name) = name.strip_prefix('!') {
        (CallMode::Application, name)
    } else if let Some(name) = name.strip_prefix('%') {
        (CallMode::Builtin, name)
    } else if is_explicit_path(name) {
        (CallMode::AbsolutePath, name)
    } else {
        (CallMode::Auto, name)
    }
}

fn is_explicit_path(name: &str) -> bool {
    name.starts_with('/')
        || name.starts_with('\\')
        || name.as_bytes().get(1) == Some(&b':')
        || name.contains('/')
        || name.contains('\\')
}

fn apply_binary(op: BinaryOp, left: &Value, right: &Value) -> Result<Value, String> {
    match op {
        BinaryOp::And => Ok(Value::Boolean(left.is_truthy() && right.is_truthy())),
        BinaryOp::Or => Ok(Value::Boolean(left.is_truthy() || right.is_truthy())),
        BinaryOp::Equal => Ok(Value::Boolean(left == right)),
        BinaryOp::NotEqual => Ok(Value::Boolean(left != right)),
        BinaryOp::Less | BinaryOp::LessEqual | BinaryOp::Greater | BinaryOp::GreaterEqual => {
            let ordering = match (left, right) {
                (Value::Integer(left), Value::Integer(right)) => left.cmp(right),
                (Value::String(left), Value::String(right)) => left.cmp(right),
                _ => return Err("comparison requires two integers or two strings".into()),
            };
            Ok(Value::Boolean(match op {
                BinaryOp::Less => ordering == Ordering::Less,
                BinaryOp::LessEqual => ordering != Ordering::Greater,
                BinaryOp::Greater => ordering == Ordering::Greater,
                BinaryOp::GreaterEqual => ordering != Ordering::Less,
                _ => unreachable!(),
            }))
        }
    }
}
