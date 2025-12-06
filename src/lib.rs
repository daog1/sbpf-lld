//! SBPF Linker 完整实现
//!
//! 基于原始 sbpf-linker 的完整流程：
//! 1. 使用 bpf-linker 链接多个输入文件
//! 2. 应用 SBPF 特定的字节级别重定位处理
//! 3. 生成完整的 SBPF 共享对象

use std::borrow::Cow;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

pub mod elf_builder;
pub mod murmur3;
pub mod raw_parser;

#[cfg(any(
    feature = "rust-llvm-19",
    feature = "rust-llvm-20",
    feature = "rust-llvm-21"
))]
use aya_rustc_llvm_proxy as _;
pub use elf_builder::{ElfBuildError, build_sbpf_so};
pub use raw_parser::{RawRelocation, RawSbpfData, RawSbpfError};

/// 检测输入文件中的 Solana syscalls
fn detect_sol_syscalls(inputs: &[PathBuf]) -> Result<HashSet<Cow<'static, str>>, RawSbpfError> {
    use object::{Object as _, ObjectSymbol as _};

    let mut syscalls = HashSet::new();
    for path in inputs {
        if let Ok(data) = fs::read(path) {
            if let Ok(obj) = object::File::parse(&*data) {
                for sym in obj.symbols() {
                    if sym.section_index().is_none() {
                        if let Ok(name) = sym.name() {
                            if raw_parser::REGISTERED_SYSCALLS.contains(&name) {
                                syscalls.insert(Cow::Owned(name.to_string()));
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(syscalls)
}

/// 使用 bpf-linker 链接多个输入文件
fn link_with_bpf_linker(inputs: &[PathBuf], temp_output: &PathBuf) -> Result<(), RawSbpfError> {
    use bpf_linker::{Cpu, Linker, LinkerOptions, OptLevel, OutputType};

    // 检测需要导出的 syscalls
    let mut export_symbols = detect_sol_syscalls(inputs)?;
    export_symbols.insert(Cow::Borrowed("entrypoint")); // 确保导出入口点

    println!("导出符号: {:?}", export_symbols);

    let mut linker = Linker::new(LinkerOptions {
        target: None,
        cpu: Cpu::V2,  // 使用BPF v2指令集
        cpu_features: String::new(),
        inputs: inputs.to_vec(),
        output: temp_output.clone(),
        output_type: OutputType::Object,
        libs: Vec::new(),
        optimize: OptLevel::No,
        export_symbols,
        unroll_loops: false,
        ignore_inline_never: false,
        dump_module: None,
        llvm_args: Vec::new(),
        disable_expand_memcpy_in_order: true,
        disable_memory_builtins: true,  // 禁用内存内置函数
        btf: false,
        allow_bpf_trap: false,
    });

    linker.link().map_err(|e| {
        RawSbpfError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Linker error: {:?}", e),
        ))
    })?;

    Ok(())
}

/// 完整的 SBPF 链接函数
pub fn full_link_program(inputs: &[PathBuf]) -> Result<Vec<u8>, RawSbpfError> {
    // 创建临时文件用于 bpf-linker 输出
    let temp_output = PathBuf::from("temp_linked.o");

    // 1. 使用 bpf-linker 链接输入文件
    link_with_bpf_linker(inputs, &temp_output)?;

    // 2. 读取链接结果
    let linked_bytes = fs::read(&temp_output)?;
    println!("bpf-linker输出文件大小: {} 字节", linked_bytes.len());

    // 3. 清理临时文件
    let _ = fs::remove_file(&temp_output);

    println!("bpf-linker 输出: {} 字节", linked_bytes.len());

    // 4. 解析链接后的文件并应用 SBPF 转换
    let mut sbpf_data = RawSbpfData::from_object_file(&linked_bytes)?;

    // 5. 应用重定位
    sbpf_data.apply_relocations()?;

    // 6. 构建最终的 .so 文件
    let output_bytes = build_sbpf_so(&sbpf_data).map_err(|e| match e {
        ElfBuildError::ObjectWrite(e) => RawSbpfError::from(e),
    })?;

    Ok(output_bytes)
}

/// 简化的 SBPF 链接函数 (向后兼容)
pub fn simple_link_program(input_bytes: &[u8]) -> Result<Vec<u8>, RawSbpfError> {
    // 解析输入的 .o 文件
    let mut sbpf_data = RawSbpfData::from_object_file(input_bytes)?;

    // 应用重定位
    sbpf_data.apply_relocations()?;

    // 构建最终的 .so 文件
    let output_bytes = build_sbpf_so(&sbpf_data).map_err(|e| match e {
        ElfBuildError::ObjectWrite(e) => RawSbpfError::from(e),
    })?;

    Ok(output_bytes)
}
