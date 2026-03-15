//! Abstract Syntax Tree for the Urego language.

#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    U64,
    I64,
    U32,
    Bool,
    Address,  // 20-byte array
    StringT,
    Bytes,
    Unit,     // ()  — no return value
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
pub struct Contract {
    pub name:      String,
    pub functions: Vec<Function>,
}

// ── Statements ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Stmt {
    /// let name: Type = expr;
    Let { name: String, ty: Option<Type>, init: Expr },
    /// name = expr;
    Assign { name: String, value: Expr },
    /// return expr;
    Return(Option<Expr>),
    /// if cond { ... } else { ... }
    If { cond: Expr, then: Vec<Stmt>, else_: Option<Vec<Stmt>> },
    /// while cond { ... }
    While { cond: Expr, body: Vec<Stmt> },
    /// expr;  (expression used as statement)
    Expr(Expr),
}

// ── Expressions ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Expr {
    /// Integer literal
    IntLit(u64),
    /// String literal
    StrLit(String),
    /// Boolean literal
    BoolLit(bool),
    /// Variable reference
    Var(String),
    /// Binary operation: left op right
    BinOp { op: BinOp, left: Box<Expr>, right: Box<Expr> },
    /// Unary operation
    UnOp { op: UnOp, expr: Box<Expr> },
    /// storage.set("key", val)  /  storage.get_u64("key")  etc.
    StorageCall { method: String, args: Vec<Expr> },
    /// events.emit("topic", val)
    EventsCall { method: String, args: Vec<Expr> },
    /// sys.caller() / sys.block_height() / sys.timestamp() / sys.contract_addr()
    SysCall { method: String },
    /// egoc_transfer(to_expr, amount_expr)
    EgocTransfer { to: Box<Expr>, amount: Box<Expr> },
    /// assert(cond, "message")
    Assert { cond: Box<Expr>, msg: String },
    /// blake3_hash(data_expr) — returns 32-byte hash as bytes
    Blake3Hash { data: Box<Expr> },
    /// Free function call: name(args)
    Call { name: String, args: Vec<Expr> },
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
