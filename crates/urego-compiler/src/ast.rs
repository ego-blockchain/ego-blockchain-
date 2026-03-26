#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    U64,
    I64,
    U32,
    Bool,
    Address,
    StringT,
    Bytes,
    Unit,

    U8,
    U16,
    U128,

    Vec(Box<Type>),
    Map(Box<Type>, Box<Type>),
    Custom(String),
}

#[derive(Debug, Clone)]
pub struct Param {
    pub name: String,
    pub ty:   Type,
}

#[derive(Debug, Clone)]
pub struct Function {
    pub name:    String,
    pub params:  Vec<Param>,
    pub ret:     Type,
    pub body:    Vec<Stmt>,
}

#[derive(Debug, Clone)]
pub struct StructField {
    pub name: String,
    pub ty:   Type,
}

#[derive(Debug, Clone)]
pub struct StructDef {
    pub name:   String,
    pub fields: Vec<StructField>,
}

#[derive(Debug, Clone)]
pub struct Contract {
    pub name:      String,
    pub structs:   Vec<StructDef>,
    pub functions: Vec<Function>,
}

#[derive(Debug, Clone)]
pub enum Stmt {

    Let { name: String, ty: Option<Type>, init: Expr },

    Assign { name: String, value: Expr },

    Return(Option<Expr>),

    If { cond: Expr, then: Vec<Stmt>, else_: Option<Vec<Stmt>> },

    While { cond: Expr, body: Vec<Stmt> },

    Expr(Expr),

    For { var: String, iter: Expr, body: Vec<Stmt> },

    CompoundAssign { name: String, op: BinOp, value: Expr },

    Match { expr: Expr, arms: Vec<MatchArm> },

    Emit { event: String, fields: Vec<(String, Expr)> },

    Break,

    Continue,
}

#[derive(Debug, Clone)]
pub struct MatchArm {
    pub pattern: Pattern,
    pub body:    Vec<Stmt>,
}

#[derive(Debug, Clone)]
pub enum Pattern {
    IntLit(u64),
    BoolLit(bool),
    StrLit(String),
    Wildcard,
    Var(String),
}

#[derive(Debug, Clone)]
pub enum Expr {

    IntLit(u64),

    StrLit(String),

    BoolLit(bool),

    Var(String),

    BinOp { op: BinOp, left: Box<Expr>, right: Box<Expr> },

    UnOp { op: UnOp, expr: Box<Expr> },

    StorageCall { method: String, args: Vec<Expr> },

    EventsCall { method: String, args: Vec<Expr> },

    SysCall { method: String },

    EgocTransfer { to: Box<Expr>, amount: Box<Expr> },

    Assert { cond: Box<Expr>, msg: String },

    Blake3Hash { data: Box<Expr> },

    Call { name: String, args: Vec<Expr> },

    ArrayLit(Vec<Expr>),

    Index { base: Box<Expr>, index: Box<Expr> },

    StructLit { name: String, fields: Vec<(String, Expr)> },

    FieldAccess { base: Box<Expr>, field: String },

    Cast { expr: Box<Expr>, to: Type },

    Range { start: Box<Expr>, end: Box<Expr> },

    Tuple(Vec<Expr>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum BinOp {
    Add, Sub, Mul, Div, Rem,
    Eq, NotEq, Lt, Gt, LtEq, GtEq,
    And, Or,
}

#[derive(Debug, Clone, PartialEq)]
pub enum UnOp {
    Neg, Not,
}
