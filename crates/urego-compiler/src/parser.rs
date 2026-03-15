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
            Token::TyU64    => { self.advance(); Ok(Type::U64)     }
            Token::TyI64    => { self.advance(); Ok(Type::I64)     }
            Token::TyU32    => { self.advance(); Ok(Type::U32)     }
            Token::TyBool   => { self.advance(); Ok(Type::Bool)    }
            Token::TyAddress => { self.advance(); Ok(Type::Address) }
            Token::TyString => { self.advance(); Ok(Type::StringT) }
            Token::TyBytes  => { self.advance(); Ok(Type::Bytes)   }
            Token::LParen   => {
                self.advance();
                self.expect(&Token::RParen)?;
                Ok(Type::Unit)
            }
            t => Err(CompileError::ParseError {
                line: self.line(),
                msg: format!("expected type, got {:?}", t),
            }),
        }
    }

    // ── Top level ─────────────────────────────────────────────────────────────

    pub fn parse_contract(&mut self) -> Result<Contract> {
        self.expect(&Token::Contract)?;
        let name = self.expect_ident()?;
        self.expect(&Token::LBrace)?;

        let mut functions = Vec::new();
        while self.peek() != &Token::RBrace && self.peek() != &Token::Eof {
            functions.push(self.parse_function()?);
        }
        self.expect(&Token::RBrace)?;

        Ok(Contract { name, functions })
    }

    fn parse_function(&mut self) -> Result<Function> {
        self.expect(&Token::Fn)?;
        let name = self.expect_ident()?;
        self.expect(&Token::LParen)?;

        let mut params = Vec::new();
        while self.peek() != &Token::RParen {
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

    // ── Statements ────────────────────────────────────────────────────────────

    fn parse_stmt(&mut self) -> Result<Stmt> {
        match self.peek().clone() {
            Token::Let => {
                self.advance();
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
            Token::If => self.parse_if(),
            Token::While => self.parse_while(),
            Token::Ident(name) => {
                // Could be assignment or expression statement
                let name = name.clone();
                // peek ahead
                if self.tokens.get(self.pos + 1).map(|s| &s.token) == Some(&Token::Assign) {
                    self.advance(); // consume ident
                    self.advance(); // consume =
                    let value = self.parse_expr()?;
                    self.expect(&Token::Semi)?;
                    Ok(Stmt::Assign { name, value })
                } else {
                    let e = self.parse_expr()?;
                    self.expect(&Token::Semi)?;
                    Ok(Stmt::Expr(e))
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

    // ── Expressions (precedence climbing) ────────────────────────────────────

    fn parse_expr(&mut self) -> Result<Expr> {
        self.parse_or()
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
        let mut left = self.parse_unary()?;
        loop {
            let op = match self.peek() {
                Token::Star    => BinOp::Mul,
                Token::Slash   => BinOp::Div,
                Token::Percent => BinOp::Rem,
                _ => break,
            };
            self.advance();
            let right = self.parse_unary()?;
            left = Expr::BinOp { op, left: Box::new(left), right: Box::new(right) };
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Expr> {
        match self.peek().clone() {
            Token::Minus => {
                self.advance();
                let e = self.parse_primary()?;
                Ok(Expr::UnOp { op: UnOp::Neg, expr: Box::new(e) })
            }
            Token::Bang => {
                self.advance();
                let e = self.parse_primary()?;
                Ok(Expr::UnOp { op: UnOp::Not, expr: Box::new(e) })
            }
            _ => self.parse_postfix(),
        }
    }

    fn parse_postfix(&mut self) -> Result<Expr> {
        let mut base = self.parse_primary()?;
        // handle method chaining: base.method(args)
        while self.peek() == &Token::Dot {
            self.advance();
            let method = self.expect_ident()?;
            self.expect(&Token::LParen)?;
            let args = self.parse_args()?;
            self.expect(&Token::RParen)?;
            // Rewrite based on receiver
            base = match &base {
                Expr::Var(v) if v == "storage" =>
                    Expr::StorageCall { method, args },
                Expr::Var(v) if v == "events" =>
                    Expr::EventsCall { method, args },
                Expr::Var(v) if v == "sys" =>
                    Expr::SysCall { method },
                _ => Expr::Call { name: method, args },
            };
        }
        Ok(base)
    }

    fn parse_primary(&mut self) -> Result<Expr> {
        match self.peek().clone() {
            Token::IntLit(n)     => { self.advance(); Ok(Expr::IntLit(n)) }
            Token::StrLit(s)     => { self.advance(); Ok(Expr::StrLit(s)) }
            Token::True          => { self.advance(); Ok(Expr::BoolLit(true))  }
            Token::False         => { self.advance(); Ok(Expr::BoolLit(false)) }

            Token::LParen => {
                self.advance();
                let e = self.parse_expr()?;
                self.expect(&Token::RParen)?;
                Ok(e)
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
                        // function call or variable
                        if self.peek() == &Token::LParen {
                            self.advance();
                            let args = self.parse_args()?;
                            self.expect(&Token::RParen)?;
                            Ok(Expr::Call { name, args })
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
        while self.peek() != &Token::RParen {
            args.push(self.parse_expr()?);
            if self.peek() == &Token::Comma { self.advance(); }
        }
        Ok(args)
    }
}
