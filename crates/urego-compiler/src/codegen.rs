use crate::ast::*;
use crate::error::{CompileError, Result};
use std::collections::HashMap;

const SCRATCH_U64:  u32 = 4096;
const SCRATCH_ADDR: u32 = 4104;
const DATA_BASE:    u32 = 0;
const DATA_LIMIT:   u32 = 4096;

const BUMP_BASE: u32 = 4124;

pub struct Codegen {

    str_offsets: HashMap<String, (u32, u32)>,
    data_ptr:    u32,
    output:      String,
}

impl Codegen {
    pub fn new() -> Self {
        Self {
            str_offsets: HashMap::new(),
            data_ptr:    DATA_BASE,
            output:      String::new(),
        }
    }

    fn intern_str(&mut self, s: &str) -> Result<(u32, u32)> {
        if let Some(&pair) = self.str_offsets.get(s) {
            return Ok(pair);
        }
        let offset = self.data_ptr;
        let len    = s.len() as u32;
        if offset + len >= DATA_LIMIT {
            return Err(CompileError::CodegenError(
                "string literal data section overflow — max 4 KB of string literals".into()
            ));
        }
        self.str_offsets.insert(s.to_string(), (offset, len));
        self.data_ptr += len + 1;
        Ok((offset, len))
    }

    fn intern_str_get(&self, s: &str) -> Result<(u32, u32)> {
        self.str_offsets.get(s).copied().ok_or_else(|| {
            CompileError::CodegenError(format!("string '{}' not interned", s))
        })
    }

    fn collect_strings(&mut self, contract: &Contract) -> Result<()> {
        for f in &contract.functions {
            self.collect_strings_stmts(&f.body)?;
        }
        for f in &contract.functions {
            self.collect_emit_names(&f.body)?;
        }
        Ok(())
    }

    fn collect_emit_names(&mut self, stmts: &[Stmt]) -> Result<()> {
        for s in stmts {
            match s {
                Stmt::Emit { event, fields } => {
                    self.intern_str(event)?;
                    for (_, e) in fields { self.collect_strings_expr(e)?; }
                }
                Stmt::For { body, iter, .. } => {
                    self.collect_strings_expr(iter)?;
                    self.collect_emit_names(body)?;
                }
                Stmt::While { cond, body } => {
                    self.collect_strings_expr(cond)?;
                    self.collect_emit_names(body)?;
                }
                Stmt::If { cond, then, else_ } => {
                    self.collect_strings_expr(cond)?;
                    self.collect_emit_names(then)?;
                    if let Some(b) = else_ { self.collect_emit_names(b)?; }
                }
                Stmt::Match { expr, arms } => {
                    self.collect_strings_expr(expr)?;
                    for arm in arms { self.collect_emit_names(&arm.body)?; }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn collect_strings_stmts(&mut self, stmts: &[Stmt]) -> Result<()> {
        for s in stmts {
            match s {
                Stmt::Let { init, .. }     => self.collect_strings_expr(init)?,
                Stmt::Assign { value, .. } => self.collect_strings_expr(value)?,
                Stmt::Return(Some(e))      => self.collect_strings_expr(e)?,
                Stmt::If { cond, then, else_ } => {
                    self.collect_strings_expr(cond)?;
                    self.collect_strings_stmts(then)?;
                    if let Some(b) = else_ { self.collect_strings_stmts(b)?; }
                }
                Stmt::While { cond, body } => {
                    self.collect_strings_expr(cond)?;
                    self.collect_strings_stmts(body)?;
                }
                Stmt::For { iter, body, .. } => {
                    self.collect_strings_expr(iter)?;
                    self.collect_strings_stmts(body)?;
                }
                Stmt::CompoundAssign { value, .. } => self.collect_strings_expr(value)?,
                Stmt::Match { expr, arms } => {
                    self.collect_strings_expr(expr)?;
                    for arm in arms { self.collect_strings_stmts(&arm.body)?; }
                }
                Stmt::Emit { fields, .. } => {
                    for (_, e) in fields { self.collect_strings_expr(e)?; }
                }
                Stmt::Expr(e) => self.collect_strings_expr(e)?,
                _ => {}
            }
        }
        Ok(())
    }

    fn collect_strings_expr(&mut self, expr: &Expr) -> Result<()> {
        match expr {
            Expr::StrLit(s)                  => { self.intern_str(s)?; }
            Expr::BinOp { left, right, .. }  => {
                self.collect_strings_expr(left)?;
                self.collect_strings_expr(right)?;
            }
            Expr::UnOp { expr, .. }          => self.collect_strings_expr(expr)?,
            Expr::StorageCall { args, .. }   => { for a in args { self.collect_strings_expr(a)?; } }
            Expr::EventsCall  { args, .. }   => { for a in args { self.collect_strings_expr(a)?; } }
            Expr::Assert { cond, msg }       => {
                self.collect_strings_expr(cond)?;
                self.intern_str(msg)?;
            }
            Expr::EgocTransfer { to, amount } => {
                self.collect_strings_expr(to)?;
                self.collect_strings_expr(amount)?;
            }
            Expr::Call { args, .. }          => { for a in args { self.collect_strings_expr(a)?; } }
            Expr::Blake3Hash { data }        => self.collect_strings_expr(data)?,
            Expr::ArrayLit(elems)            => { for e in elems { self.collect_strings_expr(e)?; } }
            Expr::Index { base, index }      => {
                self.collect_strings_expr(base)?;
                self.collect_strings_expr(index)?;
            }
            Expr::StructLit { fields, .. }   => {
                for (_, e) in fields { self.collect_strings_expr(e)?; }
            }
            Expr::FieldAccess { base, .. }   => self.collect_strings_expr(base)?,
            Expr::Cast { expr, .. }          => self.collect_strings_expr(expr)?,
            Expr::Range { start, end }       => {
                self.collect_strings_expr(start)?;
                self.collect_strings_expr(end)?;
            }
            Expr::Tuple(elems)               => { for e in elems { self.collect_strings_expr(e)?; } }
            _ => {}
        }
        Ok(())
    }

    pub fn generate(&mut self, contract: &Contract) -> Result<String> {

        self.collect_strings(contract)?;

        let mut wat = String::new();
        wat.push_str("(module\n");

        wat.push_str("  ;; Host imports\n");

        wat.push_str("  (import \"env\" \"storage_get\" (func $storage_get (param i32 i32 i32 i32 i32) (result i32)))\n");

        wat.push_str("  (import \"env\" \"storage_set\" (func $storage_set (param i32 i32 i32 i32 i32 i32)))\n");

        wat.push_str("  (import \"env\" \"storage_del\" (func $storage_del (param i32 i32 i32 i32)))\n");

        wat.push_str("  (import \"env\" \"events_emit\" (func $events_emit (param i32 i32 i32 i32)))\n");

        wat.push_str("  (import \"env\" \"blake3_hash\" (func $blake3_hash (param i32 i32 i32)))\n");
        wat.push_str("  (import \"env\" \"sys_caller\" (func $sys_caller (param i32) (result i32)))\n");
        wat.push_str("  (import \"env\" \"sys_block_height\" (func $sys_block_height (result i64)))\n");
        wat.push_str("  (import \"env\" \"sys_timestamp\" (func $sys_timestamp (result i64)))\n");
        wat.push_str("  (import \"env\" \"sys_contract_addr\" (func $sys_contract_addr (param i32) (result i32)))\n");

        wat.push_str("  (import \"env\" \"egoc_transfer\" (func $egoc_transfer (param i32 i32 i64)))\n");

        wat.push_str("  (import \"env\" \"urego_assert\" (func $urego_assert (param i32)))\n\n");

        wat.push_str("  (memory 1)\n");
        wat.push_str("  (export \"memory\" (memory 0))\n\n");

        if !self.str_offsets.is_empty() {

            let mut entries: Vec<(&String, &(u32, u32))> = self.str_offsets.iter().collect();
            entries.sort_by_key(|&(_, &(off, _))| off);
            for (s, (off, _)) in entries {
                let escaped = s.replace('\\', "\\\\").replace('"', "\\\"")
                    .replace('\n', "\\n").replace('\t', "\\t");
                wat.push_str(&format!("  (data (i32.const {off}) \"{escaped}\\00\")\n"));
            }
            wat.push('\n');
        }

        wat.push_str("  ;; Helper: read u64 from storage\n");
        wat.push_str("  (func $__get_u64 (param $kp i32) (param $kl i32) (result i64)\n");
        wat.push_str(&format!("    (drop (call $storage_get (i32.const 0) (i32.const 0) (local.get $kp) (local.get $kl) (i32.const {SCRATCH_U64})))\n"));
        wat.push_str(&format!("    (i64.load (i32.const {SCRATCH_U64}))\n"));
        wat.push_str("  )\n\n");

        wat.push_str("  ;; Helper: write u64 to storage\n");
        wat.push_str("  (func $__set_u64 (param $kp i32) (param $kl i32) (param $v i64)\n");
        wat.push_str(&format!("    (i64.store (i32.const {SCRATCH_U64}) (local.get $v))\n"));
        wat.push_str(&format!("    (call $storage_set (i32.const 0) (i32.const 0) (local.get $kp) (local.get $kl) (i32.const {SCRATCH_U64}) (i32.const 8))\n"));
        wat.push_str("  )\n\n");

        for func in &contract.functions {
            let func_wat = self.gen_function(func)?;
            wat.push_str(&func_wat);
            wat.push('\n');
        }

        wat.push_str(")\n");
        Ok(wat)
    }

    fn gen_function(&self, func: &Function) -> Result<String> {
        let mut w = String::new();
        let fname = &func.name;

        let mut locals: HashMap<String, Type> = HashMap::new();
        for p in &func.params {
            locals.insert(p.name.clone(), p.ty.clone());
        }
        self.collect_locals_stmts(&func.body, &mut locals);

        let needs_match_val = self.stmts_have_match(&func.body);
        if needs_match_val {
            locals.insert("__match_val".into(), Type::U64);
        }

        let params_wat: String = func.params.iter()
            .map(|p| format!("(param ${} {})", p.name, wasm_type(&p.ty)))
            .collect::<Vec<_>>().join(" ");
        let ret_wat = match &func.ret {
            Type::Unit => String::new(),
            t => format!(" (result {})", wasm_type(t)),
        };

        w.push_str(&format!("  (func ${fname} (export \"{fname}\") {params_wat}{ret_wat}\n"));

        let param_names: std::collections::HashSet<&str> =
            func.params.iter().map(|p| p.name.as_str()).collect();
        for (lname, lty) in &locals {
            if !param_names.contains(lname.as_str()) {
                w.push_str(&format!("    (local ${lname} {})\n", wasm_type(lty)));
            }
        }

        let mut body_ctx = FuncCtx { locals: locals.clone() };
        for stmt in &func.body {
            let s = self.gen_stmt(stmt, &mut body_ctx, &func.ret)?;
            w.push_str(&s);
        }

        w.push_str("  )\n");
        Ok(w)
    }

    fn stmts_have_match(&self, stmts: &[Stmt]) -> bool {
        stmts.iter().any(|s| match s {
            Stmt::Match { .. } => true,
            Stmt::If { then, else_, .. } => {
                self.stmts_have_match(then)
                    || else_.as_ref().map_or(false, |b| self.stmts_have_match(b))
            }
            Stmt::While { body, .. } | Stmt::For { body, .. } => self.stmts_have_match(body),
            _ => false,
        })
    }

    fn collect_locals_stmts(&self, stmts: &[Stmt], locals: &mut HashMap<String, Type>) {
        for s in stmts {
            match s {
                Stmt::Let { name, ty, .. } => {
                    let t = ty.clone().unwrap_or(Type::U64);
                    locals.insert(name.clone(), t);
                }
                Stmt::If { then, else_, .. } => {
                    self.collect_locals_stmts(then, locals);
                    if let Some(b) = else_ { self.collect_locals_stmts(b, locals); }
                }
                Stmt::While { body, .. } => self.collect_locals_stmts(body, locals),
                Stmt::For { var, body, .. } => {

                    locals.insert(var.clone(), Type::U64);
                    self.collect_locals_stmts(body, locals);
                }
                Stmt::Match { arms, .. } => {
                    for arm in arms { self.collect_locals_stmts(&arm.body, locals); }
                }
                Stmt::CompoundAssign { .. } => {}
                Stmt::Emit { .. } => {}
                _ => {}
            }
        }
    }

    fn gen_stmt(&self, stmt: &Stmt, ctx: &mut FuncCtx, ret: &Type) -> Result<String> {
        let mut w = String::new();
        match stmt {
            Stmt::Let { name, init, .. } => {
                w.push_str(&self.gen_expr(init, ctx)?);
                w.push_str(&format!("    (local.set ${name})\n"));
            }
            Stmt::Assign { name, value } => {
                w.push_str(&self.gen_expr(value, ctx)?);
                w.push_str(&format!("    (local.set ${name})\n"));
            }
            Stmt::Return(Some(e)) => {
                w.push_str(&self.gen_expr(e, ctx)?);
                w.push_str("    (return)\n");
            }
            Stmt::Return(None) => {
                w.push_str("    (return)\n");
            }
            Stmt::If { cond, then, else_ } => {

                w.push_str(&self.gen_expr(cond, ctx)?);
                w.push_str("    (i32.wrap_i64)\n");
                let result_type = if *ret != Type::Unit { format!(" (result {})", wasm_type(ret)) } else { String::new() };
                w.push_str(&format!("    (if{result_type}\n      (then\n"));
                for s in then { w.push_str(&self.gen_stmt(s, ctx, ret)?); }
                w.push_str("      )\n");
                if let Some(eb) = else_ {
                    w.push_str("      (else\n");
                    for s in eb { w.push_str(&self.gen_stmt(s, ctx, ret)?); }
                    w.push_str("      )\n");
                }
                w.push_str("    )\n");
            }
            Stmt::While { cond, body } => {
                w.push_str("    (block $for_break\n");
                w.push_str("      (loop $for_continue\n");

                w.push_str(&self.gen_expr(cond, ctx)?);
                w.push_str("        (i64.eqz)\n");
                w.push_str("        (br_if $for_break)\n");
                for s in body { w.push_str(&self.gen_stmt(s, ctx, ret)?); }
                w.push_str("        (br $for_continue)\n");
                w.push_str("      )\n");
                w.push_str("    )\n");
            }
            Stmt::For { var, iter, body } => {
                match iter {
                    Expr::Range { start, end } => {

                        w.push_str(&self.gen_expr(start, ctx)?);
                        w.push_str(&format!("    (local.set ${var})\n"));

                        w.push_str("    (block $for_break\n");
                        w.push_str("      (loop $for_continue\n");

                        w.push_str(&format!("        (local.get ${var})\n"));
                        w.push_str(&self.gen_expr(end, ctx)?);
                        w.push_str("        (i64.ge_u)\n");
                        w.push_str("        (br_if $for_break)\n");

                        for s in body { w.push_str(&self.gen_stmt(s, ctx, ret)?); }

                        w.push_str(&format!("        (local.get ${var})\n"));
                        w.push_str("        (i64.const 1)\n");
                        w.push_str("        (i64.add)\n");
                        w.push_str(&format!("        (local.set ${var})\n"));
                        w.push_str("        (br $for_continue)\n");
                        w.push_str("      )\n");
                        w.push_str("    )\n");
                    }
                    _ => return Err(CompileError::CodegenError(
                        "for..in only supports range expressions (start..end) in Phase 1".into()
                    )),
                }
            }
            Stmt::CompoundAssign { name, op, value } => {
                w.push_str(&format!("    (local.get ${name})\n"));
                w.push_str(&self.gen_expr(value, ctx)?);
                let instr = match op {
                    BinOp::Add => "i64.add",
                    BinOp::Sub => "i64.sub",
                    _ => return Err(CompileError::CodegenError(
                        "only += and -= compound assignments are supported".into()
                    )),
                };
                w.push_str(&format!("    ({instr})\n"));
                w.push_str(&format!("    (local.set ${name})\n"));
            }
            Stmt::Match { expr, arms } => {

                w.push_str(&self.gen_expr(expr, ctx)?);
                w.push_str("    (local.set $__match_val)\n");

                let mut open_ifs = 0usize;
                for arm in arms {
                    match &arm.pattern {
                        Pattern::Wildcard | Pattern::Var(_) => {

                            for s in &arm.body { w.push_str(&self.gen_stmt(s, ctx, ret)?); }
                        }
                        Pattern::IntLit(n) => {
                            w.push_str(&format!("    (local.get $__match_val)\n"));
                            w.push_str(&format!("    (i64.const {n})\n"));
                            w.push_str("    (i64.eq)\n");
                            w.push_str("    (if\n      (then\n");
                            for s in &arm.body { w.push_str(&self.gen_stmt(s, ctx, ret)?); }
                            w.push_str("      )\n");
                            open_ifs += 1;
                        }
                        Pattern::BoolLit(b) => {
                            w.push_str(&format!("    (local.get $__match_val)\n"));
                            w.push_str(&format!("    (i64.const {})\n", if *b { 1 } else { 0 }));
                            w.push_str("    (i64.eq)\n");
                            w.push_str("    (if\n      (then\n");
                            for s in &arm.body { w.push_str(&self.gen_stmt(s, ctx, ret)?); }
                            w.push_str("      )\n");
                            open_ifs += 1;
                        }
                        Pattern::StrLit(_) => {

                            return Err(CompileError::CodegenError(
                                "string patterns in match not supported in Phase 1".into()
                            ));
                        }
                    }

                    if matches!(arm.pattern, Pattern::IntLit(_) | Pattern::BoolLit(_)) {
                        w.push_str("    )\n");
                        open_ifs -= 1;
                    }
                }

                for _ in 0..open_ifs { w.push_str("    )\n"); }
            }
            Stmt::Emit { event, fields } => {

                let (toff, tlen) = self.intern_str_get(event)?;

                if let Some((_, first_val)) = fields.first() {

                    w.push_str(&format!("    (i32.const {SCRATCH_U64})\n"));
                    w.push_str(&self.gen_expr(first_val, ctx)?);
                    w.push_str("    (i64.store)\n");
                    w.push_str(&format!("    (call $events_emit (i32.const {toff}) (i32.const {tlen}) (i32.const {SCRATCH_U64}) (i32.const 8))\n"));
                } else {
                    w.push_str(&format!("    (call $events_emit (i32.const {toff}) (i32.const {tlen}) (i32.const 0) (i32.const 0))\n"));
                }
            }
            Stmt::Break => {
                w.push_str("    (br $for_break)\n");
            }
            Stmt::Continue => {
                w.push_str("    (br $for_continue)\n");
            }
            Stmt::Expr(e) => {
                let code = self.gen_expr(e, ctx)?;
                w.push_str(&code);

                w.push_str("    (drop)\n");
            }
        }
        Ok(w)
    }

    fn gen_expr(&self, expr: &Expr, ctx: &mut FuncCtx) -> Result<String> {
        let mut w = String::new();
        match expr {
            Expr::IntLit(n)  => w.push_str(&format!("    (i64.const {n})\n")),
            Expr::BoolLit(b) => w.push_str(&format!("    (i64.const {})\n", if *b { 1 } else { 0 })),
            Expr::StrLit(_)  => {
                return Err(CompileError::CodegenError(
                    "string literals can only be used as arguments to storage/events calls".into()
                ));
            }

            Expr::Var(name) => {
                w.push_str(&format!("    (local.get ${name})\n"));
            }

            Expr::BinOp { op, left, right } => {
                w.push_str(&self.gen_expr(left, ctx)?);
                w.push_str(&self.gen_expr(right, ctx)?);
                match op {

                    BinOp::Add => w.push_str("    (i64.add)\n"),
                    BinOp::Sub => w.push_str("    (i64.sub)\n"),
                    BinOp::Mul => w.push_str("    (i64.mul)\n"),
                    BinOp::Div => w.push_str("    (i64.div_u)\n"),
                    BinOp::Rem => w.push_str("    (i64.rem_u)\n"),

                    BinOp::Eq    => { w.push_str("    (i64.eq)\n");    w.push_str("    (i64.extend_i32_u)\n"); }
                    BinOp::NotEq => { w.push_str("    (i64.ne)\n");    w.push_str("    (i64.extend_i32_u)\n"); }
                    BinOp::Lt    => { w.push_str("    (i64.lt_u)\n");  w.push_str("    (i64.extend_i32_u)\n"); }
                    BinOp::Gt    => { w.push_str("    (i64.gt_u)\n");  w.push_str("    (i64.extend_i32_u)\n"); }
                    BinOp::LtEq  => { w.push_str("    (i64.le_u)\n");  w.push_str("    (i64.extend_i32_u)\n"); }
                    BinOp::GtEq  => { w.push_str("    (i64.ge_u)\n");  w.push_str("    (i64.extend_i32_u)\n"); }

                    BinOp::And => w.push_str("    (i64.and)\n"),
                    BinOp::Or  => w.push_str("    (i64.or)\n"),
                }
            }

            Expr::UnOp { op, expr } => {
                match op {
                    UnOp::Neg => {
                        w.push_str("    (i64.const 0)\n");
                        w.push_str(&self.gen_expr(expr, ctx)?);
                        w.push_str("    (i64.sub)\n");
                    }
                    UnOp::Not => {

                        w.push_str(&self.gen_expr(expr, ctx)?);
                        w.push_str("    (i64.eqz)\n");
                        w.push_str("    (i64.extend_i32_u)\n");
                    }
                }
            }

            Expr::StorageCall { method, args } => {
                match method.as_str() {
                    "get_u64" | "get" => {
                        let key = self.require_str_arg(args, 0, "storage.get_u64")?;
                        let (off, len) = self.str_offsets[key];
                        w.push_str(&format!("    (call $__get_u64 (i32.const {off}) (i32.const {len}))\n"));
                    }
                    "set" => {
                        let key = self.require_str_arg(args, 0, "storage.set")?;
                        let (off, len) = self.str_offsets[key];

                        w.push_str(&format!("    (i32.const {off})\n"));
                        w.push_str(&format!("    (i32.const {len})\n"));
                        w.push_str(&self.gen_expr(&args[1], ctx)?);
                        w.push_str("    (call $__set_u64)\n");
                        w.push_str("    (i64.const 0)\n");
                    }
                    "del" => {
                        let key = self.require_str_arg(args, 0, "storage.del")?;
                        let (off, len) = self.str_offsets[key];

                        w.push_str("    (i32.const 0)\n");
                        w.push_str("    (i32.const 0)\n");
                        w.push_str(&format!("    (i32.const {off})\n"));
                        w.push_str(&format!("    (i32.const {len})\n"));
                        w.push_str("    (call $storage_del)\n");
                        w.push_str("    (i64.const 0)\n");
                    }
                    m => return Err(CompileError::CodegenError(
                        format!("unknown storage method: {m}")
                    )),
                }
            }

            Expr::EventsCall { method, args } => {
                match method.as_str() {
                    "emit" => {
                        let topic = self.require_str_arg(args, 0, "events.emit")?;
                        let (toff, tlen) = self.str_offsets[topic];

                        w.push_str(&format!("    (i32.const {SCRATCH_U64})\n"));
                        w.push_str(&self.gen_expr(&args[1], ctx)?);
                        w.push_str("    (i64.store)\n");
                        w.push_str(&format!("    (call $events_emit (i32.const {toff}) (i32.const {tlen}) (i32.const {SCRATCH_U64}) (i32.const 8))\n"));
                        w.push_str("    (i64.const 0)\n");
                    }
                    m => return Err(CompileError::CodegenError(
                        format!("unknown events method: {m}")
                    )),
                }
            }

            Expr::SysCall { method } => {
                match method.as_str() {
                    "block_height" => w.push_str("    (call $sys_block_height)\n"),
                    "timestamp"    => w.push_str("    (call $sys_timestamp)\n"),
                    "caller"       => {
                        w.push_str(&format!("    (call $sys_caller (i32.const {SCRATCH_ADDR}))\n"));
                        w.push_str("    (drop)\n");
                        w.push_str(&format!("    (i64.const {SCRATCH_ADDR})\n"));
                    }
                    "contract_addr" => {
                        w.push_str(&format!("    (call $sys_contract_addr (i32.const {SCRATCH_ADDR}))\n"));
                        w.push_str("    (drop)\n");
                        w.push_str(&format!("    (i64.const {SCRATCH_ADDR})\n"));
                    }
                    m => return Err(CompileError::CodegenError(
                        format!("unknown sys method: {m}")
                    )),
                }
            }

            Expr::EgocTransfer { to, amount } => {
                w.push_str(&self.gen_expr(to, ctx)?);
                w.push_str("    (i32.wrap_i64)\n");
                w.push_str(&self.gen_expr(amount, ctx)?);
                w.push_str("    (call $egoc_transfer)\n");
                w.push_str("    (i64.extend_i32_u)\n");
            }

            Expr::Assert { cond, .. } => {

                w.push_str(&self.gen_expr(cond, ctx)?);
                w.push_str("    (i32.wrap_i64)\n");
                w.push_str("    (call $urego_assert)\n");
                w.push_str("    (i64.const 0)\n");
            }

            Expr::Blake3Hash { data } => {
                w.push_str(&self.gen_expr(data, ctx)?);
                w.push_str("    (i32.wrap_i64)\n");
                w.push_str("    (i32.const 32)\n");
                w.push_str(&format!("    (i32.const {SCRATCH_ADDR})\n"));

                w.push_str("    (call $blake3_hash)\n");
                w.push_str(&format!("    (i64.const {SCRATCH_ADDR})\n"));
            }

            Expr::Call { name, args } => {
                for a in args { w.push_str(&self.gen_expr(a, ctx)?); }
                w.push_str(&format!("    (call ${name})\n"));
            }

            Expr::Cast { expr, to } => {
                w.push_str(&self.gen_expr(expr, ctx)?);
                match to {
                    Type::U32 | Type::U8 | Type::U16 | Type::Bool => {
                        w.push_str("    (i32.wrap_i64)\n");
                    }
                    Type::U64 | Type::I64 | Type::U128 => {

                    }
                    _ => {

                    }
                }
            }

            Expr::Range { .. } => {

                return Err(CompileError::CodegenError(
                    "range expression (..) is only valid inside a for..in statement".into()
                ));
            }

            Expr::ArrayLit(elems) => {

                let _byte_size = elems.len() as u32 * 8;

                for e in elems {
                    w.push_str(&self.gen_expr(e, ctx)?);
                    w.push_str("    (drop)\n");
                }
                w.push_str(&format!("    (i64.const {BUMP_BASE})\n"));
            }

            Expr::Index { base, index } => {

                w.push_str(&self.gen_expr(base, ctx)?);
                w.push_str("    (i32.wrap_i64)\n");
                w.push_str(&self.gen_expr(index, ctx)?);
                w.push_str("    (i64.const 8)\n");
                w.push_str("    (i64.mul)\n");
                w.push_str("    (i32.wrap_i64)\n");
                w.push_str("    (i32.add)\n");
                w.push_str("    (i64.load)\n");
            }

            Expr::StructLit { name, fields } => {

                let _ = name;
                for (_, e) in fields {
                    w.push_str(&self.gen_expr(e, ctx)?);
                    w.push_str("    (drop)\n");
                }
                w.push_str(&format!("    (i64.const {BUMP_BASE})\n"));
            }

            Expr::FieldAccess { base, field } => {

                let _ = field;
                w.push_str(&self.gen_expr(base, ctx)?);
            }

            Expr::Tuple(elems) => {

                match elems.len() {
                    0 => w.push_str("    (i64.const 0)\n"),
                    1 => w.push_str(&self.gen_expr(&elems[0], ctx)?),
                    _ => return Err(CompileError::CodegenError(
                        "multi-element tuples are not supported in Phase 1 codegen".into()
                    )),
                }
            }
        }
        Ok(w)
    }

    fn require_str_arg<'a>(&self, args: &'a [Expr], idx: usize, ctx: &str) -> Result<&'a str> {
        match args.get(idx) {
            Some(Expr::StrLit(s)) => Ok(s.as_str()),
            _ => Err(CompileError::CodegenError(
                format!("{ctx} argument {idx} must be a string literal")
            )),
        }
    }
}

fn wasm_type(ty: &Type) -> &'static str {
    match ty {
        Type::U64 | Type::I64 | Type::StringT | Type::Bytes | Type::Address => "i64",
        Type::U32 | Type::Bool => "i32",

        Type::U8 | Type::U16 => "i32",
        Type::U128 => "i64",

        Type::Vec(_) | Type::Map(_, _) | Type::Custom(_) => "i64",
        Type::Unit => "",
    }
}

struct FuncCtx {
    locals: HashMap<String, Type>,
}
