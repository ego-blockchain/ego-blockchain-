use crate::error::{CompileError, Result};

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    // Keywords
    Contract, Fn, Let, Return, If, Else, While, True, False,
    // Types
    TyU64, TyI64, TyU32, TyBool, TyAddress, TyString, TyBytes,
    // Literals
    IntLit(u64),
    StrLit(String),
    // Operators
    Plus, Minus, Star, Slash, Percent,
    EqEq, NotEq, Lt, Gt, LtEq, GtEq,
    And, Or, Bang,
    Assign,
    Arrow,  // ->
    // Punctuation
    LBrace, RBrace, LParen, RParen, LBracket, RBracket,
    Comma, Semi, Colon, Dot,
    // Identifier
    Ident(String),
    // EOF
    Eof,
}

#[derive(Debug, Clone)]
pub struct Spanned {
    pub token: Token,
    pub line:  usize,
}

pub fn lex(src: &str) -> Result<Vec<Spanned>> {
    let mut tokens = Vec::new();
    let mut chars   = src.char_indices().peekable();
    let mut line    = 1usize;

    while let Some((i, ch)) = chars.next() {
        match ch {
            '\n' => { line += 1; }
            ' ' | '\t' | '\r' => {}

            '/' => {
                // line comment
                if chars.peek().map(|&(_, c)| c) == Some('/') {
                    while let Some((_, c)) = chars.next() {
                        if c == '\n' { line += 1; break; }
                    }
                } else {
                    tokens.push(Spanned { token: Token::Slash, line });
                }
            }

            '"' => {
                let mut s = String::new();
                loop {
                    match chars.next() {
                        Some((_, '"'))  => break,
                        Some((_, '\\')) => {
                            match chars.next() {
                                Some((_, 'n'))  => s.push('\n'),
                                Some((_, 't'))  => s.push('\t'),
                                Some((_, '"'))  => s.push('"'),
                                Some((_, '\\')) => s.push('\\'),
                                _ => {}
                            }
                        }
                        Some((_, c))    => s.push(c),
                        None => return Err(CompileError::LexError {
                            line, msg: "unterminated string literal".into()
                        }),
                    }
                }
                tokens.push(Spanned { token: Token::StrLit(s), line });
            }

            '0'..='9' => {
                let mut num = String::new();
                num.push(ch);
                while let Some(&(_, c)) = chars.peek() {
                    if c.is_ascii_digit() || c == '_' {
                        chars.next();
                        if c != '_' { num.push(c); }
                    } else { break; }
                }
                // swallow optional type suffix: u64, i64, u32
                if chars.peek().map(|&(_, c)| c.is_alphabetic()) == Some(true) {
                    let mut suffix = String::new();
                    while let Some(&(_, c)) = chars.peek() {
                        if c.is_alphanumeric() { chars.next(); suffix.push(c); }
                        else { break; }
                    }
                    // ignore suffix — treat all int literals as u64
                }
                let v: u64 = num.parse().map_err(|_| CompileError::LexError {
                    line, msg: format!("invalid integer: {num}")
                })?;
                tokens.push(Spanned { token: Token::IntLit(v), line });
            }

            'a'..='z' | 'A'..='Z' | '_' => {
                let mut ident = String::new();
                ident.push(ch);
                while let Some(&(_, c)) = chars.peek() {
                    if c.is_alphanumeric() || c == '_' { chars.next(); ident.push(c); }
                    else { break; }
                }
                let tok = match ident.as_str() {
                    "contract" => Token::Contract,
                    "fn"       => Token::Fn,
                    "let"      => Token::Let,
                    "return"   => Token::Return,
                    "if"       => Token::If,
                    "else"     => Token::Else,
                    "while"    => Token::While,
                    "true"     => Token::True,
                    "false"    => Token::False,
                    "u64"      => Token::TyU64,
                    "i64"      => Token::TyI64,
                    "u32"      => Token::TyU32,
                    "bool"     => Token::TyBool,
                    "Address"  => Token::TyAddress,
                    "String"   => Token::TyString,
                    "Bytes"    => Token::TyBytes,
                    _          => Token::Ident(ident),
                };
                tokens.push(Spanned { token: tok, line });
            }

            '{' => tokens.push(Spanned { token: Token::LBrace,   line }),
            '}' => tokens.push(Spanned { token: Token::RBrace,   line }),
            '(' => tokens.push(Spanned { token: Token::LParen,   line }),
            ')' => tokens.push(Spanned { token: Token::RParen,   line }),
            '[' => tokens.push(Spanned { token: Token::LBracket, line }),
            ']' => tokens.push(Spanned { token: Token::RBracket, line }),
            ',' => tokens.push(Spanned { token: Token::Comma,    line }),
            ';' => tokens.push(Spanned { token: Token::Semi,     line }),
            ':' => tokens.push(Spanned { token: Token::Colon,    line }),
            '.' => tokens.push(Spanned { token: Token::Dot,      line }),
            '+' => tokens.push(Spanned { token: Token::Plus,     line }),
            '*' => tokens.push(Spanned { token: Token::Star,     line }),
            '%' => tokens.push(Spanned { token: Token::Percent,  line }),

            '-' => {
                if chars.peek().map(|&(_, c)| c) == Some('>') {
                    chars.next();
                    tokens.push(Spanned { token: Token::Arrow, line });
                } else {
                    tokens.push(Spanned { token: Token::Minus, line });
                }
            }
            '=' => {
                if chars.peek().map(|&(_, c)| c) == Some('=') {
                    chars.next();
                    tokens.push(Spanned { token: Token::EqEq, line });
                } else {
                    tokens.push(Spanned { token: Token::Assign, line });
                }
            }
            '!' => {
                if chars.peek().map(|&(_, c)| c) == Some('=') {
                    chars.next();
                    tokens.push(Spanned { token: Token::NotEq, line });
                } else {
                    tokens.push(Spanned { token: Token::Bang, line });
                }
            }
            '<' => {
                if chars.peek().map(|&(_, c)| c) == Some('=') {
                    chars.next();
                    tokens.push(Spanned { token: Token::LtEq, line });
                } else {
                    tokens.push(Spanned { token: Token::Lt, line });
                }
            }
            '>' => {
                if chars.peek().map(|&(_, c)| c) == Some('=') {
                    chars.next();
                    tokens.push(Spanned { token: Token::GtEq, line });
                } else {
                    tokens.push(Spanned { token: Token::Gt, line });
                }
            }
            '&' => {
                if chars.peek().map(|&(_, c)| c) == Some('&') {
                    chars.next();
                    tokens.push(Spanned { token: Token::And, line });
                } else {
                    return Err(CompileError::LexError { line, msg: "use && for logical and".into() });
                }
            }
            '|' => {
                if chars.peek().map(|&(_, c)| c) == Some('|') {
                    chars.next();
                    tokens.push(Spanned { token: Token::Or, line });
                } else {
                    return Err(CompileError::LexError { line, msg: "use || for logical or".into() });
                }
            }

            c => return Err(CompileError::LexError {
                line, msg: format!("unexpected character: {c:?}")
            }),
        }
    }

    tokens.push(Spanned { token: Token::Eof, line });
    Ok(tokens)
}
