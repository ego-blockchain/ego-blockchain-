use crate::ast::*;
use crate::error::{CompileError, Result};
use crate::lexer::{Spanned, Token};

pub struct Parser {
    tokens: Vec<Spanned>,
    pos:    usize,
}

impl Parser {
    pub fn new(tokens: Vec<Spanned>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> &Token {
        &self.tokens[self.pos].token
    }

    fn line(&self) -> usize {
        self.tokens[self.pos].line
    }

    fn advance(&mut self) -> &Token {
        let t = &self.tokens[self.pos].token;
        if self.pos + 1 < self.tokens.len() { self.pos += 1; }
        t
    }

    fn expect(&mut self, expected: &Token) -> Result<()> {
        if self.peek() == expected {
            self.advance();
            Ok(())
        } else {
            Err(CompileError::ParseError {
                line: self.line(),
                msg: format!("expected {:?}, got {:?}", expected, self.peek()),
            })
        }
    }

    fn expect_ident(&mut self) -> Result<String> {
        match self.peek().clone() {
            Token::Ident(s) => { self.advance(); Ok(s) }
            t => Err(CompileError::ParseError {
                line: self.line(),
                msg: format!("expected identifier, got {:?}", t),
            }),
        }
    }

    fn parse_type(&mut self) -> Result<Type> {
        match self.peek().clone() {
            Token::TyU64     => { self.advance(); Ok(Type::U64)     }
            Token::TyI64     => { self.advance(); Ok(Type::I64)     }
            Token::TyU32     => { self.advance(); Ok(Type::U32)     }
            Token::TyBool    => { self.advance(); Ok(Type::Bool)    }
            Token::TyAddress => { self.advance(); Ok(Type::Address) }
            Token::TyString  => { self.advance(); Ok(Type::StringT) }
            Token::TyBytes   => { self.advance(); Ok(Type::Bytes)   }
            Token::TyU8      => { self.advance(); Ok(Type::U8)      }
            Token::TyU16     => { self.advance(); Ok(Type::U16)     }
            Token::TyU128    => { self.advance(); Ok(Type::U128)    }
            Token::TyVec     => {
                self.advance();
                self.expect(&Token::Lt)?;
                let inner = self.parse_type()?;
                self.expect(&Token::Gt)?;
                Ok(Type::Vec(Box::new(inner)))
            }
            Token::TyMap     => {
                self.advance();
                self.expect(&Token::Lt)?;
                let k = self.parse_type()?;
                self.expect(&Token::Comma)?;
                let v = self.parse_type()?;
                self.expect(&Token::Gt)?;
                Ok(Type::Map(Box::new(k), Box::new(v)))
            }
            Token::LParen    => {
                self.advance();
                self.expect(&Token::RParen)?;
                Ok(Type::Unit)
            }
            Token::Ident(name) => {
                let n = name.clone();
                self.advance();
                Ok(Type::Custom(n))
            }
            t => Err(CompileError::ParseError {
                line: self.line(),
                msg: format!("expected type, got {:?}", t),
            }),
        }
    }

    pub fn parse_contract(&mut self) -> Result<Contract> {
        self.expect(&Token::Contract)?;
        let name = self.expect_ident()?;
        self.expect(&Token::LBrace)?;

        let mut structs = Vec::new();
        loop {

            let is_pub_struct = self.peek() == &Token::Pub
                && self.tokens.get(self.pos + 1).map(|s| &s.token) == Some(&Token::Struct);
            let is_struct = self.peek() == &Token::Struct;

            if is_pub_struct {
                self.advance();
                structs.push(self.parse_struct()?);
            } else if is_struct {
                structs.push(self.parse_struct()?);
            } else {
                break;
            }
        }

        let mut functions = Vec::new();
        while self.peek() != &Token::RBrace && self.peek() != &Token::Eof {

            if self.peek() == &Token::Pub {
                self.advance();
            }
            functions.push(self.parse_function()?);
        }
        self.expect(&Token::RBrace)?;

        Ok(Contract { name, structs, functions })
    }

    fn parse_struct(&mut self) -> Result<StructDef> {
        self.expect(&Token::Struct)?;
        let name = self.expect_ident()?;
        self.expect(&Token::LBrace)?;
        let mut fields = Vec::new();
        while self.peek() != &Token::RBrace && self.peek() != &Token::Eof {

            if self.peek() == &Token::Pub { self.advance(); }
            let fname = self.expect_ident()?;
            self.expect(&Token::Colon)?;
            let ty = self.parse_type()?;
            fields.push(StructField { name: fname, ty });
            if self.peek() == &Token::Comma { self.advance(); }
        }
        self.expect(&Token::RBrace)?;
        Ok(StructDef { name, fields })
    }

    fn parse_function(&mut self) -> Result<Function> {
        self.expect(&Token::Fn)?;
        let name = self.expect_ident()?;
        self.expect(&Token::LParen)?;

        let mut params = Vec::new();
        while self.peek() != &Token::RParen {

            if self.peek() == &Token::Mut { self.advance(); }
            let pname = self.expect_ident()?;
            self.expect(&Token::Colon)?;
            let ty = self.parse_type()?;
            params.push(Param { name: pname, ty });
            if self.peek() == &Token::Comma { self.advance(); }
        }
        self.expect(&Token::RParen)?;

        let ret = if self.peek() == &Token::Arrow {
            self.advance();
            self.parse_type()?
        } else {
            Type::Unit
        };

        self.expect(&Token::LBrace)?;
        let body = self.parse_block()?;
        self.expect(&Token::RBrace)?;

        Ok(Function { name, params, ret, body })
    }

    fn parse_block(&mut self) -> Result<Vec<Stmt>> {
        let mut stmts = Vec::new();
        while self.peek() != &Token::RBrace && self.peek() != &Token::Eof {
            stmts.push(self.parse_stmt()?);
        }
        Ok(stmts)
    }

    fn parse_stmt(&mut self) -> Result<Stmt> {
        match self.peek().clone() {
            Token::Let => {
                self.advance();

                if self.peek() == &Token::Mut { self.advance(); }
                let name = self.expect_ident()?;
                let ty = if self.peek() == &Token::Colon {
                    self.advance();
                    Some(self.parse_type()?)
                } else { None };
                self.expect(&Token::Assign)?;
                let init = self.parse_expr()?;
                self.expect(&Token::Semi)?;
                Ok(Stmt::Let { name, ty, init })
            }
            Token::Return => {
                self.advance();
                if self.peek() == &Token::Semi {
                    self.advance();
                    Ok(Stmt::Return(None))
                } else {
                    let e = self.parse_expr()?;
                    self.expect(&Token::Semi)?;
                    Ok(Stmt::Return(Some(e)))
                }
            }
            Token::If      => self.parse_if(),
            Token::While   => self.parse_while(),
            Token::For     => self.parse_for(),
            Token::Match   => self.parse_match(),
            Token::Emit    => self.parse_emit_stmt(),
            Token::Break   => {
                self.advance();
                self.expect(&Token::Semi)?;
                Ok(Stmt::Break)
            }
            Token::Continue => {
                self.advance();
                self.expect(&Token::Semi)?;
                Ok(Stmt::Continue)
            }
            Token::Ident(name) => {
                let name = name.clone();

                let next = self.tokens.get(self.pos + 1).map(|s| s.token.clone());
                match next {
                    Some(Token::Assign) => {
                        self.advance();
                        self.advance();
                        let value = self.parse_expr()?;
                        self.expect(&Token::Semi)?;
                        Ok(Stmt::Assign { name, value })
                    }
                    Some(Token::PlusEq) => {
                        self.advance();
                        self.advance();
                        let value = self.parse_expr()?;
                        self.expect(&Token::Semi)?;
                        Ok(Stmt::CompoundAssign { name, op: BinOp::Add, value })
                    }
                    Some(Token::MinusEq) => {
                        self.advance();
                        self.advance();
                        let value = self.parse_expr()?;
                        self.expect(&Token::Semi)?;
                        Ok(Stmt::CompoundAssign { name, op: BinOp::Sub, value })
                    }
                    _ => {
                        let e = self.parse_expr()?;
                        self.expect(&Token::Semi)?;
                        Ok(Stmt::Expr(e))
                    }
                }
            }
            _ => {
                let e = self.parse_expr()?;
                self.expect(&Token::Semi)?;
                Ok(Stmt::Expr(e))
            }
        }
    }

    fn parse_if(&mut self) -> Result<Stmt> {
        self.expect(&Token::If)?;
        let cond = self.parse_expr()?;
        self.expect(&Token::LBrace)?;
        let then = self.parse_block()?;
        self.expect(&Token::RBrace)?;

        let else_ = if self.peek() == &Token::Else {
            self.advance();
            self.expect(&Token::LBrace)?;
            let b = self.parse_block()?;
            self.expect(&Token::RBrace)?;
            Some(b)
        } else { None };

        Ok(Stmt::If { cond, then, else_ })
    }

    fn parse_while(&mut self) -> Result<Stmt> {
        self.expect(&Token::While)?;
        let cond = self.parse_expr()?;
        self.expect(&Token::LBrace)?;
        let body = self.parse_block()?;
        self.expect(&Token::RBrace)?;
        Ok(Stmt::While { cond, body })
    }

    fn parse_for(&mut self) -> Result<Stmt> {
        self.expect(&Token::For)?;

        if self.peek() == &Token::Mut { self.advance(); }
        let var = self.expect_ident()?;
        self.expect(&Token::In)?;
        let iter = self.parse_expr()?;
        self.expect(&Token::LBrace)?;
        let body = self.parse_block()?;
        self.expect(&Token::RBrace)?;
        Ok(Stmt::For { var, iter, body })
    }

    fn parse_match(&mut self) -> Result<Stmt> {
        self.expect(&Token::Match)?;
        let expr = self.parse_expr()?;
        self.expect(&Token::LBrace)?;
        let mut arms = Vec::new();
        while self.peek() != &Token::RBrace && self.peek() != &Token::Eof {
            let pattern = self.parse_pattern()?;
            self.expect(&Token::FatArrow)?;
            self.expect(&Token::LBrace)?;
            let body = self.parse_block()?;
            self.expect(&Token::RBrace)?;
            arms.push(MatchArm { pattern, body });
            if self.peek() == &Token::Comma { self.advance(); }
        }
        self.expect(&Token::RBrace)?;
        Ok(Stmt::Match { expr, arms })
    }

    fn parse_pattern(&mut self) -> Result<Pattern> {
        match self.peek().clone() {
            Token::IntLit(n)                  => { self.advance(); Ok(Pattern::IntLit(n)) }
            Token::True                        => { self.advance(); Ok(Pattern::BoolLit(true)) }
            Token::False                       => { self.advance(); Ok(Pattern::BoolLit(false)) }
            Token::StrLit(s)                   => { self.advance(); Ok(Pattern::StrLit(s)) }
            Token::Ident(s) if s == "_"        => { self.advance(); Ok(Pattern::Wildcard) }
            Token::Ident(s)                    => { let s = s.clone(); self.advance(); Ok(Pattern::Var(s)) }
            t => Err(CompileError::ParseError {
                line: self.line(),
                msg: format!("expected pattern, got {:?}", t),
            }),
        }
    }

    fn parse_emit_stmt(&mut self) -> Result<Stmt> {
        self.expect(&Token::Emit)?;
        let event = self.expect_ident()?;
        self.expect(&Token::LBrace)?;
        let mut fields = Vec::new();
        while self.peek() != &Token::RBrace && self.peek() != &Token::Eof {
            let fname = self.expect_ident()?;
            self.expect(&Token::Colon)?;
            let val = self.parse_expr()?;
            fields.push((fname, val));
            if self.peek() == &Token::Comma { self.advance(); }
        }
        self.expect(&Token::RBrace)?;
        self.expect(&Token::Semi)?;
        Ok(Stmt::Emit { event, fields })
    }

    fn parse_expr(&mut self) -> Result<Expr> {
        self.parse_range()
    }

    fn parse_range(&mut self) -> Result<Expr> {
        let left = self.parse_or()?;
        if self.peek() == &Token::DotDot {
            self.advance();
            let right = self.parse_or()?;
            Ok(Expr::Range { start: Box::new(left), end: Box::new(right) })
        } else {
            Ok(left)
        }
    }

    fn parse_or(&mut self) -> Result<Expr> {
        let mut left = self.parse_and()?;
        while self.peek() == &Token::Or {
            self.advance();
            let right = self.parse_and()?;
            left = Expr::BinOp { op: BinOp::Or, left: Box::new(left), right: Box::new(right) };
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr> {
        let mut left = self.parse_cmp()?;
        while self.peek() == &Token::And {
            self.advance();
            let right = self.parse_cmp()?;
            left = Expr::BinOp { op: BinOp::And, left: Box::new(left), right: Box::new(right) };
        }
        Ok(left)
    }

    fn parse_cmp(&mut self) -> Result<Expr> {
        let mut left = self.parse_add()?;
        loop {
            let op = match self.peek() {
                Token::EqEq  => BinOp::Eq,
                Token::NotEq => BinOp::NotEq,
                Token::Lt    => BinOp::Lt,
                Token::Gt    => BinOp::Gt,
                Token::LtEq  => BinOp::LtEq,
                Token::GtEq  => BinOp::GtEq,
                _ => break,
            };
            self.advance();
            let right = self.parse_add()?;
            left = Expr::BinOp { op, left: Box::new(left), right: Box::new(right) };
        }
        Ok(left)
    }

    fn parse_add(&mut self) -> Result<Expr> {
        let mut left = self.parse_mul()?;
        loop {
            let op = match self.peek() {
                Token::Plus  => BinOp::Add,
                Token::Minus => BinOp::Sub,
                _ => break,
            };
            self.advance();
            let right = self.parse_mul()?;
            left = Expr::BinOp { op, left: Box::new(left), right: Box::new(right) };
        }
        Ok(left)
    }

    fn parse_mul(&mut self) -> Result<Expr> {
        let mut left = self.parse_cast()?;
        loop {
            let op = match self.peek() {
                Token::Star    => BinOp::Mul,
                Token::Slash   => BinOp::Div,
                Token::Percent => BinOp::Rem,
                _ => break,
            };
            self.advance();
            let right = self.parse_cast()?;
            left = Expr::BinOp { op, left: Box::new(left), right: Box::new(right) };
        }
        Ok(left)
    }

    fn parse_cast(&mut self) -> Result<Expr> {
        let mut e = self.parse_unary()?;
        while self.peek() == &Token::As {
            self.advance();
            let to = self.parse_type()?;
            e = Expr::Cast { expr: Box::new(e), to };
        }
        Ok(e)
    }

    fn parse_unary(&mut self) -> Result<Expr> {
        match self.peek().clone() {
            Token::Minus => {
                self.advance();
                let e = self.parse_postfix()?;
                Ok(Expr::UnOp { op: UnOp::Neg, expr: Box::new(e) })
            }
            Token::Bang => {
                self.advance();
                let e = self.parse_postfix()?;
                Ok(Expr::UnOp { op: UnOp::Not, expr: Box::new(e) })
            }
            _ => self.parse_postfix(),
        }
    }

    fn parse_postfix(&mut self) -> Result<Expr> {
        let mut base = self.parse_primary()?;

        loop {
            match self.peek() {
                Token::Dot => {
                    self.advance();
                    let field_or_method = self.expect_ident()?;
                    if self.peek() == &Token::LParen {

                        self.advance();
                        let args = self.parse_args()?;
                        self.expect(&Token::RParen)?;
                        base = match &base {
                            Expr::Var(v) if v == "storage" =>
                                Expr::StorageCall { method: field_or_method, args },
                            Expr::Var(v) if v == "events" =>
                                Expr::EventsCall { method: field_or_method, args },
                            Expr::Var(v) if v == "sys" =>
                                Expr::SysCall { method: field_or_method },
                            _ => Expr::Call { name: field_or_method, args },
                        };
                    } else {

                        base = Expr::FieldAccess { base: Box::new(base), field: field_or_method };
                    }
                }
                Token::LBracket => {

                    self.advance();
                    let idx = self.parse_expr()?;
                    self.expect(&Token::RBracket)?;
                    base = Expr::Index { base: Box::new(base), index: Box::new(idx) };
                }
                _ => break,
            }
        }
        Ok(base)
    }

    fn parse_primary(&mut self) -> Result<Expr> {
        match self.peek().clone() {
            Token::IntLit(n) => { self.advance(); Ok(Expr::IntLit(n)) }
            Token::StrLit(s) => { self.advance(); Ok(Expr::StrLit(s)) }
            Token::True      => { self.advance(); Ok(Expr::BoolLit(true))  }
            Token::False     => { self.advance(); Ok(Expr::BoolLit(false)) }

            Token::LBracket => {
                self.advance();
                let mut elems = Vec::new();
                while self.peek() != &Token::RBracket && self.peek() != &Token::Eof {
                    elems.push(self.parse_expr()?);
                    if self.peek() == &Token::Comma { self.advance(); }
                }
                self.expect(&Token::RBracket)?;
                Ok(Expr::ArrayLit(elems))
            }

            Token::LParen => {
                self.advance();

                if self.peek() == &Token::RParen {
                    self.advance();
                    return Ok(Expr::Tuple(Vec::new()));
                }
                let first = self.parse_expr()?;
                if self.peek() == &Token::Comma {

                    self.advance();
                    let mut elems = vec![first];
                    while self.peek() != &Token::RParen && self.peek() != &Token::Eof {
                        elems.push(self.parse_expr()?);
                        if self.peek() == &Token::Comma { self.advance(); }
                    }
                    self.expect(&Token::RParen)?;
                    Ok(Expr::Tuple(elems))
                } else {
                    self.expect(&Token::RParen)?;
                    Ok(first)
                }
            }

            Token::Ident(name) => {
                let name = name.clone();
                self.advance();
                match name.as_str() {
                    "assert" => {
                        self.expect(&Token::LParen)?;
                        let cond = self.parse_expr()?;
                        self.expect(&Token::Comma)?;
                        let msg = match self.parse_expr()? {
                            Expr::StrLit(s) => s,
                            _ => return Err(CompileError::ParseError {
                                line: self.line(),
                                msg: "assert message must be a string literal".into(),
                            }),
                        };
                        self.expect(&Token::RParen)?;
                        Ok(Expr::Assert { cond: Box::new(cond), msg })
                    }
                    "egoc_transfer" => {
                        self.expect(&Token::LParen)?;
                        let to = self.parse_expr()?;
                        self.expect(&Token::Comma)?;
                        let amount = self.parse_expr()?;
                        self.expect(&Token::RParen)?;
                        Ok(Expr::EgocTransfer {
                            to:     Box::new(to),
                            amount: Box::new(amount),
                        })
                    }
                    "blake3_hash" => {
                        self.expect(&Token::LParen)?;
                        let data = self.parse_expr()?;
                        self.expect(&Token::RParen)?;
                        Ok(Expr::Blake3Hash { data: Box::new(data) })
                    }
                    _ => {
                        if self.peek() == &Token::LParen {

                            self.advance();
                            let args = self.parse_args()?;
                            self.expect(&Token::RParen)?;
                            Ok(Expr::Call { name, args })
                        } else if self.peek() == &Token::LBrace {

                            self.advance();
                            let mut fields = Vec::new();
                            while self.peek() != &Token::RBrace && self.peek() != &Token::Eof {
                                let fname = self.expect_ident()?;
                                self.expect(&Token::Colon)?;
                                let val = self.parse_expr()?;
                                fields.push((fname, val));
                                if self.peek() == &Token::Comma { self.advance(); }
                            }
                            self.expect(&Token::RBrace)?;
                            Ok(Expr::StructLit { name, fields })
                        } else {
                            Ok(Expr::Var(name))
                        }
                    }
                }
            }

            t => Err(CompileError::ParseError {
                line: self.line(),
                msg: format!("unexpected token in expression: {:?}", t),
            }),
        }
    }

    fn parse_args(&mut self) -> Result<Vec<Expr>> {
        let mut args = Vec::new();
        while self.peek() != &Token::RParen && self.peek() != &Token::Eof {
            args.push(self.parse_expr()?);
            if self.peek() == &Token::Comma { self.advance(); }
        }
        Ok(args)
    }
}
