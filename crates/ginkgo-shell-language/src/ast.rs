use alloc::{string::String, vec::Vec};

#[derive(Clone, Copy, Debug)]
pub(crate) struct Location {
    pub line: usize,
    pub column: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct Node<T> {
    pub location: Location,
    pub value: T,
}

pub(crate) type ExprNode = Node<Expr>;
pub(crate) type Statement = Node<StatementKind>;

#[derive(Clone, Debug)]
pub(crate) enum StatementKind {
    Assignment(String, ExprNode),
    Command(String, Vec<ExprNode>),
    Expression(ExprNode),
    Include(String),
    Run(String),
    Alias(String, String),
    Definition {
        name: String,
        parameters: Vec<String>,
        body: Vec<Statement>,
    },
    For {
        variable: String,
        iterable: ExprNode,
        body: Vec<Statement>,
    },
    While {
        condition: ExprNode,
        body: Vec<Statement>,
    },
    Repeat {
        count: ExprNode,
        body: Vec<Statement>,
    },
    Until {
        condition: ExprNode,
        body: Vec<Statement>,
    },
    DoWhile {
        body: Vec<Statement>,
        condition: ExprNode,
    },
    Return(Option<ExprNode>),
}

#[derive(Clone, Debug)]
pub(crate) enum Expr {
    Value(crate::Value),
    Variable(String),
    List(Vec<ExprNode>),
    Glob(String),
    UnaryNot(alloc::boxed::Box<ExprNode>),
    Binary {
        op: BinaryOp,
        left: alloc::boxed::Box<ExprNode>,
        right: alloc::boxed::Box<ExprNode>,
    },
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum BinaryOp {
    And,
    Or,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
}
