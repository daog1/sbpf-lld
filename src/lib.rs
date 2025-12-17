//! SBPF Linker complete implementation
//!
//! Based on the complete flow of the original sbpf-linker:
//! 1. Use bpf-linker to link multiple input files
//! 2. Apply SBPF-specific byte-level relocation processing
//! 3. Generate complete SBPF shared objects

use anyhow::{Context, Result};
use std::borrow::Cow;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

pub mod elf_object;
pub mod murmur3;
pub mod raw_parser;

#[cfg(any(
    feature = "rust-llvm-19",
    feature = "rust-llvm-20",
    feature = "rust-llvm-21"
))]
use aya_rustc_llvm_proxy as _;

pub use elf_object::{ElfBuildError, build_sbpf_so};
pub use raw_parser::{RawRelocation, RawSbpfData, RawSbpfError};

/// Detect Solana syscalls in input files
fn detect_sol_syscalls(inputs: &[PathBuf]) -> Result<HashSet<Cow<'static, str>>> {
    use object::{Object as _, ObjectSymbol as _};

    let mut syscalls = HashSet::new();
    for path in inputs {
        let data = fs::read(path)
            .with_context(|| format!("Failed to read input file: {}", path.display()))?;

        let obj = object::File::parse(&*data)
            .with_context(|| format!("Failed to parse object file: {}", path.display()))?;

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
    Ok(syscalls)
}

/// Link multiple input files using bpf-linker
fn link_with_bpf_linker(inputs: &[PathBuf], temp_output: &PathBuf) -> Result<()> {
    use bpf_linker::{Cpu, Linker, LinkerOptions, OptLevel, OutputType};

    // Detect syscalls that need to be exported
    let mut export_symbols = detect_sol_syscalls(inputs)?;
    export_symbols.insert(Cow::Borrowed("entrypoint")); // Ensure entrypoint is exported

    println!("Exported symbols: {:?}", export_symbols);

    let mut linker = Linker::new(LinkerOptions {
        target: None,
        cpu: Cpu::V2, // Use BPF v2 instruction set
        cpu_features: String::new(),
        inputs: inputs.to_vec(),
        output: temp_output.clone(),
        output_type: OutputType::Object,
        libs: Vec::new(),
        optimize: OptLevel::No,
        export_symbols,
        unroll_loops: true,
        ignore_inline_never: false,
        dump_module: None,
        llvm_args: Vec::new(),
        disable_expand_memcpy_in_order: true,
        disable_memory_builtins: true, // Disable memory builtin functions
        btf: false,
        allow_bpf_trap: false,
    });

    linker
        .link()
        .with_context(|| format!("Failed to link files to {}", temp_output.display()))?;

    // Check for any linker errors or warnings
    if linker.has_errors() {
        anyhow::bail!("Linker reported errors during linking process");
    }

    Ok(())
}

/// Complete SBPF linking function
pub fn full_link_program(inputs: &[PathBuf]) -> Result<Vec<u8>> {
    // Create temporary file for bpf-linker output
    let temp_output = PathBuf::from("temp_linked.o");

    // 1. Link input files using bpf-linker
    link_with_bpf_linker(inputs, &temp_output).context("Failed during bpf-linker phase")?;

    // 2. Read the linked result
    let linked_bytes = fs::read(&temp_output).with_context(|| {
        format!(
            "Failed to read linked output file: {}",
            temp_output.display()
        )
    })?;
    println!("bpf-linker output: {} bytes", linked_bytes.len());

    // 3. Clean up temporary file
    let _ = fs::remove_file(&temp_output);

    // 4. Parse the linked file and apply SBPF transformation
    let mut sbpf_data = RawSbpfData::from_object_file(&linked_bytes)
        .context("Failed to parse linked object file")?;

    // 5. Apply relocations
    sbpf_data
        .apply_relocations()
        .context("Failed to apply relocations")?;

    // 6. Build the final .so file
    let output_bytes = build_sbpf_so(&sbpf_data).context("Failed to build final ELF file")?;

    Ok(output_bytes)
}
