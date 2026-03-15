//! WAT (WebAssembly Text Format) code generator.
//!
//! Memory layout (1 page = 64 KB):
//!   0    – 4095  : string literal data section
//!   4096 – 4103  : 8-byte scratch for u64 storage r/w
//!   4104 – 4123  : 20-byte scratch for Address r/w
//!   4124 – 8191  : dynamic bump allocator (for runtime strings)
//!   8192+        : stack / user data

use crate::ast::*;
use crate::error::{CompileError, Result};
use std::collections::HashMap;

const SCRATCH_U64:  u32 = 4096;
const SCRATCH_ADDR: u32 = 4104;
const DATA_BASE:    u32 = 0;
const DATA_LIMIT:   u32 = 4096;

pub struct Codegen {
    /// String literal → (offset, length) in data section
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

    /// Register a string literal and return (offset, len).
    fn intern_str(&mut self, s: &str) -> (u32, u32) {
        if let Some(&pair) = self.str_offsets.get(s) {
            return pair;
        }
        let offset = self.data_ptr;
        let len    = s.len() as u32;
        if offset + len >= DATA_LIMIT {
            panic!("string literal data section overflow — max 4 KB of string literals");
        }
        self.str_offsets.insert(s.to_string(), (offset, len));
        self.data_ptr += len + 1; // null-terminate for safety
        (offset, len)
    }

    /// Walk the entire contract AST to pre-intern all string literals.
    fn collect_strings(&mut self, contract: &Contract) {
        for f in &contract.functions {
            self.collect_strings_stmts(&f.body);
        }
    }

    fn collect_strings_stmts(&mut self, stmts: &[Stmt]) {
        for s in stmts {
            match s {
                Stmt::Let { init, .. }    => self.collect_strings_expr(init),
                Stmt::Assign { value, .. } => self.collect_strings_expr(value),
                Stmt::Return(Some(e))     => self.collect_strings_expr(e),
                Stmt::If { cond, then, else_ } => {
                    self.collect_strings_expr(cond);
                    self.collect_strings_stmts(then);
                    if let Some(b) = else_ { self.collect_strings_stmts(b); }
                }
                Stmt::While { cond, body } => {
                    self.collect_strings_expr(cond);
                    self.collect_strings_stmts(body);
                }
                Stmt::Expr(e) => self.collect_strings_expr(e),
                _ => {}
            }
        }
    }

    fn collect_strings_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::StrLit(s)                  => { self.intern_str(s); }
            Expr::BinOp { left, right, .. }  => {
                self.collect_strings_expr(left);
                self.collect_strings_expr(right);
            }
            Expr::UnOp { expr, .. }          => self.collect_strings_expr(expr),
            Expr::StorageCall { args, .. }   => args.iter().for_each(|a| self.collect_strings_expr(a)),
            Expr::EventsCall  { args, .. }   => args.iter().for_each(|a| self.collect_strings_expr(a)),
            Expr::Assert { cond, msg }       => {
                self.collect_strings_expr(cond);
                self.intern_str(msg);
            }
            Expr::EgocTransfer { to, amount } => {
                self.collect_strings_expr(to);
                self.collect_strings_expr(amount);
            }
            Expr::Call { args, .. }          => args.iter().for_each(|a| self.collect_strings_expr(a)),
            Expr::Blake3Hash { data }        => self.collect_strings_expr(data),
            _ => {}
        }
    }

    // ── Main entry point ──────────────────────────────────────────────────────

    pub fn generate(&mut self, contract: &Contract) -> Result<String> {
        // Pass 1: collect all string literals so offsets are stable
        self.collect_strings(contract);

        let mut wat = String::new();
        wat.push_str("(module\n");

        // Host function imports — MUST come before memory in WAT
        wat.push_str("  ;; Host imports\n");
        wat.push_str("  (import \"env\" \"storage_get\" (func $storage_get (param i32 i32 i32 i32) (result i32)))\n");
        wat.push_str("  (import \"env\" \"storage_set\" (func $storage_set (param i32 i32 i32 i32)))\n");
        wat.push_str("  (import \"env\" \"storage_del\" (func $storage_del (param i32 i32)))\n");
        wat.push_str("  (import \"env\" \"events_emit\" (func $events_emit (param i32 i32 i32 i32)))\n");
        wat.push_str("  (import \"env\" \"blake3_hash\" (func $blake3_hash (param i32 i32 i32) (result i32)))\n");
        wat.push_str("  (import \"env\" \"sys_caller\" (func $sys_caller (param i32) (result i32)))\n");
        wat.push_str("  (import \"env\" \"sys_block_height\" (func $sys_block_height (result i64)))\n");
        wat.push_str("  (import \"env\" \"sys_timestamp\" (func $sys_timestamp (result i64)))\n");
        wat.push_str("  (import \"env\" \"sys_contract_addr\" (func $sys_contract_addr (param i32) (result i32)))\n");
        wat.push_str("  (import \"env\" \"egoc_transfer\" (func $egoc_transfer (param i32 i64) (result i32)))\n");
        wat.push_str("  (import \"env\" \"urego_assert\" (func $urego_assert (param i32 i32 i32)))\n\n");

        // Memory and export
        wat.push_str("  (memory 1)\n");
        wat.push_str("  (export \"memory\" (memory 0))\n\n");

        // Data section
        if !self.str_offsets.is_empty() {
            // Sort by offset for deterministic output
            let mut entries: Vec<(&String, &(u32, u32))> = self.str_offsets.iter().collect();
            entries.sort_by_key(|&(_, &(off, _))| off);
            for (s, (off, _)) in entries {
                let escaped = s.replace('\\', "\\\\").replace('"', "\\\"")
                    .replace('\n', "\\n").replace('\t', "\\t");
                wat.push_str(&format!("  (data (i32.const {off}) \"{escaped}\\00\")\n"));
            }
            wat.push('\n');
        }

        // Helper: get_u64 from storage
        wat.push_str("  ;; Helper: read u64 from storage\n");
        wat.push_str("  (func $__get_u64 (param $kp i32) (param $kl i32) (result i64)\n");
        wat.push_str(&format!("    (drop (call $storage_get (local.get $kp) (local.get $kl) (i32.const {SCRATCH_U64}) (i32.const 8)))\n"));
        wat.push_str(&format!("    (i64.load (i32.const {SCRATCH_U64}))\n"));
        wat.push_str("  )\n\n");

        // Helper: set_u64 to storage
        wat.push_str("  ;; Helper: write u64 to storage\n");
        wat.push_str("  (func $__set_u64 (param $kp i32) (param $kl i32) (param $v i64)\n");
        wat.push_str(&format!("    (i64.store (i32.const {SCRATCH_U64}) (local.get $v))\n"));
        wat.push_str(&format!("    (call $storage_set (local.get $kp) (local.get $kl) (i32.const {SCRATCH_U64}) (i32.const 8))\n"));
        wat.push_str("  )\n\n");

        // Contract functions
        for func in &contract.functions {
            let func_wat = self.gen_function(func)?;
            wat.push_str(&func_wat);
            wat.push('\n');
        }

        wat.push_str(")\n");
        Ok(wat)
    }

    // ── Function generation ───────────────────────────────────────────────────

    fn gen_function(&self, func: &Function) -> Result<String> {
        let mut w = String::new();
        let fname = &func.name;

        // Collect locals from let statements
        let mut locals: HashMap<String, Type> = HashMap::new();
        for p in &func.params {
            locals.insert(p.name.clone(), p.ty.clone());
        }
        self.collect_locals_stmts(&func.body, &mut locals);

        // Function signature
        let params_wat: String = func.params.iter()
            .map(|p| format!("(param ${} {})", p.name, wasm_type(&p.ty)))
            .collect::<Vec<_>>().join(" ");
        let ret_wat = match &func.ret {
            Type::Unit => String::new(),
            t => format!(" (result {})", wasm_type(t)),
        };

        w.push_str(&format!("  (func ${fname} (export \"{fname}\") {params_wat}{ret_wat}\n"));

        // Declare locals that aren't parameters
        let param_names: std::collections::HashSet<&str> =
            func.params.iter().map(|p| p.name.as_str()).collect();
        for (lname, lty) in &locals {
            if !param_names.contains(lname.as_str()) {
                w.push_str(&format!("    (local ${lname} {})\n", wasm_type(lty)));
            }
        }

        // Body
        let mut body_ctx = FuncCtx { locals: locals.clone() };
        for stmt in &func.body {
            let s = self.gen_stmt(stmt, &mut body_ctx, &func.ret)?;
            w.push_str(&s);
        }

        w.push_str("  )\n");
        Ok(w)
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
                _ => {}
            }
        }
    }

    // ── Statement generation ──────────────────────────────────────────────────

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
                w.push_str("    (block $break\n");
                w.push_str("      (loop $continue\n");
                w.push_str(&self.gen_expr(cond, ctx)?);
                w.push_str("        (i32.eqz)\n");
                w.push_str("        (br_if $break)\n");
                for s in body { w.push_str(&self.gen_stmt(s, ctx, ret)?); }
                w.push_str("        (br $continue)\n");
                w.push_str("      )\n");
                w.push_str("    )\n");
            }
            Stmt::Expr(e) => {
                let code = self.gen_expr(e, ctx)?;
                w.push_str(&code);
                // If expression leaves a value on the stack, drop it
                w.push_str("    (drop)\n");
            }
        }
        Ok(w)
    }

    // ── Expression generation ─────────────────────────────────────────────────

    fn gen_expr(&self, expr: &Expr, ctx: &mut FuncCtx) -> Result<String> {
        let mut w = String::new();
        match expr {
            Expr::IntLit(n) => w.push_str(&format!("    (i64.const {n})\n")),
            Expr::BoolLit(b) => w.push_str(&format!("    (i32.const {})\n", if *b { 1 } else { 0 })),
            Expr::StrLit(_) => {
                // String literals as standalone expressions aren't common;
                // they're handled inline in StorageCall etc.
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
                let instr = match op {
                    BinOp::Add   => "i64.add",
                    BinOp::Sub   => "i64.sub",
                    BinOp::Mul   => "i64.mul",
                    BinOp::Div   => "i64.div_u",
                    BinOp::Rem   => "i64.rem_u",
                    BinOp::Eq    => "i64.eq",
                    BinOp::NotEq => "i64.ne",
                    BinOp::Lt    => "i64.lt_u",
                    BinOp::Gt    => "i64.gt_u",
                    BinOp::LtEq  => "i64.le_u",
                    BinOp::GtEq  => "i64.ge_u",
                    BinOp::And   => "i32.and",
                    BinOp::Or    => "i32.or",
                };
                w.push_str(&format!("    ({instr})\n"));
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
                        w.push_str("    (i32.eqz)\n");
                    }
                }
            }

            Expr::StorageCall { method, args } => {
                match method.as_str() {
                    "get_u64" | "get" => {
                        // storage.get_u64("key")
                        let key = self.require_str_arg(args, 0, "storage.get_u64")?;
                        let (off, len) = self.str_offsets[key];
                        w.push_str(&format!("    (call $__get_u64 (i32.const {off}) (i32.const {len}))\n"));
                    }
                    "set" => {
                        // storage.set("key", value_u64)
                        let key = self.require_str_arg(args, 0, "storage.set")?;
                        let (off, len) = self.str_offsets[key];
                        w.push_str(&self.gen_expr(&args[1], ctx)?);
                        w.push_str(&format!("    (call $__set_u64 (i32.const {off}) (i32.const {len}))\n"));
                        // set returns unit — push dummy i64 for drop at stmt level
                        w.push_str("    (i64.const 0)\n");
                    }
                    "del" => {
                        let key = self.require_str_arg(args, 0, "storage.del")?;
                        let (off, len) = self.str_offsets[key];
                        w.push_str(&format!("    (call $storage_del (i32.const {off}) (i32.const {len}))\n"));
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
                        // events.emit("topic", value_u64)
                        let topic = self.require_str_arg(args, 0, "events.emit")?;
                        let (toff, tlen) = self.str_offsets[topic];
                        // Store the u64 value into scratch, then emit as bytes
                        w.push_str(&self.gen_expr(&args[1], ctx)?);
                        w.push_str(&format!("    (i64.store (i32.const {SCRATCH_U64}))\n"));
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
                        w.push_str(&format!("    (drop)\n"));
                        w.push_str(&format!("    (i64.const {SCRATCH_ADDR})\n")); // return address as i64 ptr
                    }
                    "contract_addr" => {
                        w.push_str(&format!("    (call $sys_contract_addr (i32.const {SCRATCH_ADDR}))\n"));
                        w.push_str(&format!("    (drop)\n"));
                        w.push_str(&format!("    (i64.const {SCRATCH_ADDR})\n"));
                    }
                    m => return Err(CompileError::CodegenError(
                        format!("unknown sys method: {m}")
                    )),
                }
            }

            Expr::EgocTransfer { to, amount } => {
                // to is an Address ptr (i32), amount is u64 (i64)
                w.push_str(&self.gen_expr(to, ctx)?);
                w.push_str("    (i32.wrap_i64)\n"); // ptr is i32
                w.push_str(&self.gen_expr(amount, ctx)?);
                w.push_str("    (call $egoc_transfer)\n");
                w.push_str("    (i64.extend_i32_u)\n"); // return as i64
            }

            Expr::Assert { cond, msg } => {
                let (moff, mlen) = self.str_offsets[msg.as_str()];
                w.push_str(&self.gen_expr(cond, ctx)?);
                w.push_str("    (i32.wrap_i64)\n");
                w.push_str(&format!("    (call $urego_assert (i32.const {moff}) (i32.const {mlen}))\n"));
                // urego_assert consumes 3 args — rearrange
                // Actual signature: (param cond i32, msg_ptr i32, msg_len i32)
                // We need to push args in right order — rewrite:
                w.clear();
                w.push_str(&self.gen_expr(cond, ctx)?);
                w.push_str("    (i32.wrap_i64)\n");
                w.push_str(&format!("    (i32.const {moff})\n"));
                w.push_str(&format!("    (i32.const {mlen})\n"));
                w.push_str("    (call $urego_assert)\n");
                w.push_str("    (i64.const 0)\n");
            }

            Expr::Blake3Hash { data } => {
                w.push_str(&self.gen_expr(data, ctx)?);
                w.push_str("    (i32.wrap_i64)\n"); // input ptr
                w.push_str("    (i32.const 32)\n"); // input len (assume 32 bytes)
                w.push_str(&format!("    (i32.const {SCRATCH_ADDR})\n")); // output ptr
                w.push_str("    (call $blake3_hash)\n");
                w.push_str("    (drop)\n");
                w.push_str(&format!("    (i64.const {SCRATCH_ADDR})\n")); // return ptr as i64
            }

            Expr::Call { name, args } => {
                for a in args { w.push_str(&self.gen_expr(a, ctx)?); }
                w.push_str(&format!("    (call ${name})\n"));
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
        Type::Unit => "",
    }
}

// context tracking per-function locals
struct FuncCtx {
    locals: HashMap<String, Type>,
}
