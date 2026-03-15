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
    // New integer widths
    U8,
    U16,
    U128,
    // Compound types
    Vec(Box<Type>),                   // Vec<T>
    Map(Box<Type>, Box<Type>),        // Map<K, V>
    Custom(String),                   // user-defined struct name
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

/// A single field in a struct definition.
#[derive(Debug, Clone)]
pub struct StructField {
    pub name: String,
    pub ty:   Type,
}

/// A struct definition.
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

    // ── New statements ────────────────────────────────────────────────────────

    /// for item in iterable { ... }
    For { var: String, iter: Expr, body: Vec<Stmt> },

    /// name += expr  or  name -= expr
    CompoundAssign { name: String, op: BinOp, value: Expr },

    /// match expr { pattern => { ... }, ... }
    Match { expr: Expr, arms: Vec<MatchArm> },

    /// emit EventName { field: val, ... };
    Emit { event: String, fields: Vec<(String, Expr)> },

    /// break (inside for/while)
    Break,

    /// continue (inside for/while)
    Continue,
}

/// One arm of a match expression.
#[derive(Debug, Clone)]
pub struct MatchArm {
    pub pattern: Pattern,
    pub body:    Vec<Stmt>,
}

/// Patterns that can appear in a match arm.
#[derive(Debug, Clone)]
pub enum Pattern {
    IntLit(u64),
    BoolLit(bool),
    StrLit(String),
    Wildcard,       // _
    Var(String),    // binds to a new local (treated as wildcard + let in codegen)
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

    // ── New expressions ───────────────────────────────────────────────────────

    /// Array/Vec literal: [a, b, c]
    ArrayLit(Vec<Expr>),

    /// Index access: arr[i]
    Index { base: Box<Expr>, index: Box<Expr> },

    /// Struct literal: Point { x: 1, y: 2 }
    StructLit { name: String, fields: Vec<(String, Expr)> },

    /// Field access: obj.field  (struct field, not method call)
    FieldAccess { base: Box<Expr>, field: String },

    /// Type cast: expr as u64
    Cast { expr: Box<Expr>, to: Type },

    /// Range: start..end  (used in for loops)
    Range { start: Box<Expr>, end: Box<Expr> },

    /// Tuple: (a, b)
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
