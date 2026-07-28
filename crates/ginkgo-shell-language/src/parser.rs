use alloc::{boxed::Box, string::String, vec::Vec};

use pest::{iterators::Pair, Parser};
use pest_derive::Parser;

use crate::{
    ast::{BinaryOp, Expr, ExprNode, Location, Node, Statement, StatementKind},
    Error, Value,
};

#[derive(Parser)]
#[grammar = "shell.pest"]
struct ShellParser;

pub(crate) fn parse(source: &str, source_name: &str) -> Result<Vec<Statement>, Error> {
    let mut parsed = ShellParser::parse(Rule::program, source).map_err(|error| {
        let (line, column) = match error.line_col {
            pest::error::LineColLocation::Pos(position) => position,
            pest::error::LineColLocation::Span(start, _) => start,
        };
        Error::at(
            source_name,
            line,
            column,
            alloc::format!("syntax error: {error}"),
        )
    })?;
    let program = parsed.next().expect("pest always returns the program pair");
    let mut statements = Vec::new();
    for pair in program.into_inner() {
        if pair.as_rule() == Rule::statement_list {
            statements = parse_statement_list(pair, source_name)?;
        }
    }
    Ok(statements)
}

fn location(pair: &Pair<'_, Rule>) -> Location {
    let (line, column) = pair.as_span().start_pos().line_col();
    Location { line, column }
}

fn parse_statement_list(pair: Pair<'_, Rule>, source_name: &str) -> Result<Vec<Statement>, Error> {
    pair.into_inner()
        .filter(|pair| pair.as_rule() == Rule::statement)
        .map(|pair| parse_statement(pair, source_name))
        .collect()
}

fn parse_statement(pair: Pair<'_, Rule>, source_name: &str) -> Result<Statement, Error> {
    let pair = pair
        .into_inner()
        .next()
        .expect("statement has an inner rule");
    let loc = location(&pair);
    let kind = match pair.as_rule() {
        Rule::assignment => {
            let mut inner = pair.into_inner();
            let name = variable_name(inner.next().unwrap());
            let value = parse_expr(inner.next().unwrap(), source_name)?;
            StatementKind::Assignment(name, value)
        }
        Rule::command_stmt => {
            let mut inner = pair.into_inner();
            let name = inner.next().unwrap().as_str().into();
            let args = inner
                .next()
                .map(|arguments| {
                    arguments
                        .into_inner()
                        .map(|value| parse_expr(value, source_name))
                        .collect()
                })
                .transpose()?
                .unwrap_or_default();
            StatementKind::Command(name, args)
        }
        Rule::expression_stmt => {
            let expression = parse_expr(pair.into_inner().next().unwrap(), source_name)?;
            StatementKind::Expression(expression)
        }
        Rule::include_stmt | Rule::run_stmt => {
            let is_run = pair.as_rule() == Rule::run_stmt;
            let path = pair
                .into_inner()
                .find(|p| p.as_rule() == Rule::string)
                .unwrap();
            let path = decode_string(path, source_name)?;
            if is_run {
                StatementKind::Run(path)
            } else {
                StatementKind::Include(path)
            }
        }
        Rule::alias_stmt => {
            let mut inner = pair.into_inner();
            let name = inner
                .find(|p| p.as_rule() == Rule::identifier)
                .unwrap()
                .as_str()
                .into();
            let target = inner
                .find(|p| p.as_rule() == Rule::command_name)
                .unwrap()
                .as_str()
                .into();
            StatementKind::Alias(name, target)
        }
        Rule::definition => {
            let mut name = String::new();
            let mut parameters = Vec::new();
            let mut body = Vec::new();
            for child in pair.into_inner() {
                match child.as_rule() {
                    Rule::identifier => name = child.as_str().into(),
                    Rule::parameters => {
                        parameters = child.into_inner().map(variable_name).collect();
                    }
                    Rule::statement_list => body = parse_statement_list(child, source_name)?,
                    _ => {}
                }
            }
            StatementKind::Definition {
                name,
                parameters,
                body,
            }
        }
        Rule::for_loop => {
            let mut variable = None;
            let mut iterable = None;
            let mut body = Vec::new();
            for child in pair.into_inner() {
                match child.as_rule() {
                    Rule::variable => variable = Some(variable_name(child)),
                    Rule::expression => iterable = Some(parse_expr(child, source_name)?),
                    Rule::statement_list => body = parse_statement_list(child, source_name)?,
                    _ => {}
                }
            }
            StatementKind::For {
                variable: variable.unwrap(),
                iterable: iterable.unwrap(),
                body,
            }
        }
        Rule::while_loop | Rule::until_loop => {
            let is_until = pair.as_rule() == Rule::until_loop;
            let mut condition = None;
            let mut body = Vec::new();
            for child in pair.into_inner() {
                match child.as_rule() {
                    Rule::expression => condition = Some(parse_expr(child, source_name)?),
                    Rule::statement_list => body = parse_statement_list(child, source_name)?,
                    _ => {}
                }
            }
            let condition = condition.unwrap();
            if is_until {
                StatementKind::Until { condition, body }
            } else {
                StatementKind::While { condition, body }
            }
        }
        Rule::repeat_loop => {
            let mut count = None;
            let mut body = Vec::new();
            for child in pair.into_inner() {
                match child.as_rule() {
                    Rule::expression => count = Some(parse_expr(child, source_name)?),
                    Rule::statement_list => body = parse_statement_list(child, source_name)?,
                    _ => {}
                }
            }
            StatementKind::Repeat {
                count: count.unwrap(),
                body,
            }
        }
        Rule::do_while_loop => {
            let mut body = Vec::new();
            let mut condition = None;
            for child in pair.into_inner() {
                if child.as_rule() == Rule::statement_list {
                    body = parse_statement_list(child, source_name)?;
                } else if child.as_rule() == Rule::expression {
                    condition = Some(parse_expr(child, source_name)?);
                }
            }
            StatementKind::DoWhile {
                body,
                condition: condition.expect("do-while has a condition"),
            }
        }
        Rule::return_stmt => StatementKind::Return(
            pair.into_inner()
                .find(|p| p.as_rule() == Rule::expression)
                .map(|p| parse_expr(p, source_name))
                .transpose()?,
        ),
        _ => unreachable!("unexpected statement rule: {:?}", pair.as_rule()),
    };
    Ok(Node {
        location: loc,
        value: kind,
    })
}

fn parse_expr(pair: Pair<'_, Rule>, source_name: &str) -> Result<ExprNode, Error> {
    let loc = location(&pair);
    let rule = pair.as_rule();
    let expression = match rule {
        Rule::expression | Rule::primary | Rule::parenthesized => {
            return parse_expr(pair.into_inner().next().unwrap(), source_name);
        }
        Rule::expression_non_bare => {
            let mut inner = pair.into_inner();
            let first = inner.next().unwrap();
            if first.as_rule() == Rule::KW_NOT {
                Expr::UnaryNot(Box::new(parse_expr(inner.next().unwrap(), source_name)?))
            } else {
                return parse_expr(first, source_name);
            }
        }
        Rule::or_expression
        | Rule::and_expression
        | Rule::equality_expression
        | Rule::comparison_expression => {
            return parse_binary_chain(pair, source_name);
        }
        Rule::unary_expression => {
            let mut values: Vec<_> = pair.into_inner().collect();
            let primary = values.pop().unwrap();
            let mut value = parse_expr(primary, source_name)?;
            for operator in values.into_iter().rev() {
                if operator.as_rule() == Rule::KW_NOT {
                    value = Node {
                        location: loc,
                        value: Expr::UnaryNot(Box::new(value)),
                    };
                }
            }
            return Ok(value);
        }
        Rule::variable => Expr::Variable(variable_name(pair)),
        Rule::integer => {
            let value = pair.as_str().parse().map_err(|_| {
                Error::at(
                    source_name,
                    loc.line,
                    loc.column,
                    "integer is outside the i64 range",
                )
            })?;
            Expr::Value(Value::Integer(value))
        }
        Rule::boolean => Expr::Value(Value::Boolean(pair.as_str() == "true")),
        Rule::string => Expr::Value(Value::String(decode_string(pair, source_name)?)),
        Rule::bare => Expr::Value(Value::String(pair.as_str().into())),
        Rule::glob => Expr::Glob(pair.as_str().into()),
        Rule::list => {
            let values = pair
                .into_inner()
                .map(|p| parse_expr(p, source_name))
                .collect::<Result<_, _>>()?;
            Expr::List(values)
        }
        _ => unreachable!("unexpected expression rule: {rule:?}"),
    };
    Ok(Node {
        location: loc,
        value: expression,
    })
}

fn parse_binary_chain(pair: Pair<'_, Rule>, source_name: &str) -> Result<ExprNode, Error> {
    let loc = location(&pair);
    let mut inner = pair.into_inner();
    let mut left = parse_expr(inner.next().unwrap(), source_name)?;
    while let Some(operator) = inner.next() {
        let op = match operator.as_rule() {
            Rule::OP_AND => BinaryOp::And,
            Rule::OP_OR => BinaryOp::Or,
            Rule::OP_EQ => BinaryOp::Equal,
            Rule::OP_NE => BinaryOp::NotEqual,
            Rule::OP_LT => BinaryOp::Less,
            Rule::OP_LE => BinaryOp::LessEqual,
            Rule::OP_GT => BinaryOp::Greater,
            Rule::OP_GE => BinaryOp::GreaterEqual,
            _ => unreachable!(),
        };
        let right = parse_expr(inner.next().unwrap(), source_name)?;
        left = Node {
            location: loc,
            value: Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            },
        };
    }
    Ok(left)
}

fn variable_name(pair: Pair<'_, Rule>) -> String {
    pair.as_str()[1..].into()
}

fn decode_string(pair: Pair<'_, Rule>, source_name: &str) -> Result<String, Error> {
    let loc = location(&pair);
    let text = pair.as_str();
    let mut output = String::new();
    let mut chars = text[1..text.len() - 1].chars();
    while let Some(character) = chars.next() {
        if character == '\\' {
            let escaped = chars.next().ok_or_else(|| {
                Error::at(
                    source_name,
                    loc.line,
                    loc.column,
                    "unfinished string escape",
                )
            })?;
            output.push(match escaped {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                '\\' => '\\',
                '"' => '"',
                other => other,
            });
        } else {
            output.push(character);
        }
    }
    Ok(output)
}
