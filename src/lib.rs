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
use std::process::Command;

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

#[cfg(target_os = "macos")]
fn ensure_llvm_dylib_on_dyld_fallback_path() {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    fn has_libllvm_dylib(dir: &Path) -> bool {
        let Ok(entries) = dir.read_dir() else {
            return false;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("dylib") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            if stem.starts_with("libLLVM") {
                return true;
            }
        }
        false
    }

    let mut candidate_dirs: Vec<PathBuf> = Vec::new();
    if let Some(paths) = std::env::var_os("DYLD_FALLBACK_LIBRARY_PATH") {
        candidate_dirs.extend(std::env::split_paths(&paths));
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for mut p in std::env::split_paths(&paths) {
            p.pop();
            p.push("lib");
            candidate_dirs.push(p);
        }
    }

    if candidate_dirs.iter().any(|d| has_libllvm_dylib(d)) {
        return;
    }

    let hb_lib = Path::new("/opt/homebrew/opt/llvm/lib");
    if has_libllvm_dylib(hb_lib) {
        let mut new_paths: Vec<PathBuf> = vec![hb_lib.to_path_buf()];
        if let Some(existing) = std::env::var_os("DYLD_FALLBACK_LIBRARY_PATH") {
            new_paths.extend(std::env::split_paths(&existing));
        }
        if let Ok(joined) = std::env::join_paths(new_paths) {
            unsafe {
                std::env::set_var("DYLD_FALLBACK_LIBRARY_PATH", OsString::from(joined));
            }
        }
    }
}

/// Detect Solana syscalls in input files
fn detect_syscalls_from_bc(path: &PathBuf) -> Result<HashSet<Cow<'static, str>>> {
    let output = Command::new("llvm-nm")
        .arg("--undefined-only")
        .arg(path)
        .output()
        .with_context(|| format!("Failed to run llvm-nm on {}", path.display()))?;

    if !output.status.success() {
        anyhow::bail!(
            "llvm-nm failed on {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let mut syscalls = HashSet::new();
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let name = line.split_whitespace().last().unwrap_or("");
        if raw_parser::REGISTERED_SYSCALLS.contains(&name) {
            syscalls.insert(Cow::Owned(name.to_string()));
        }
    }
    Ok(syscalls)
}

fn detect_sol_syscalls(inputs: &[PathBuf]) -> Result<HashSet<Cow<'static, str>>> {
    use object::{Object as _, ObjectSymbol as _};

    let mut syscalls = HashSet::new();
    for path in inputs {
        if path.extension().and_then(|s| s.to_str()) == Some("bc") {
            syscalls.extend(detect_syscalls_from_bc(path)?);
            continue;
        }
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

fn prefer_bitcode_inputs(inputs: &[PathBuf]) -> Vec<PathBuf> {
    inputs
        .iter()
        .map(|path| {
            if path.extension().and_then(|s| s.to_str()) == Some("o") {
                let bc = path.with_extension("bc");
                if bc.exists() {
                    println!("Using bitcode input: {} (from {})", bc.display(), path.display());
                    return bc;
                }
            }
            path.clone()
        })
        .collect()
}

/// Link multiple input files using bpf-linker
fn link_with_bpf_linker(inputs: &[PathBuf], temp_output: &PathBuf) -> Result<()> {
    use bpf_linker::{Cpu, Linker, LinkerOptions, OptLevel, OutputType};

    #[cfg(target_os = "macos")]
    ensure_llvm_dylib_on_dyld_fallback_path();

    let bpf_stack_size: u32 = std::env::var("SBPF_LLD_BPF_STACK_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        // Solana SBPF programs have a 4KiB stack; bpf-linker defaults are often smaller.
        .unwrap_or(4096);

    let link_inputs = prefer_bitcode_inputs(inputs);

    // Detect syscalls that need to be exported
    let mut export_symbols = detect_sol_syscalls(&link_inputs)?;
    export_symbols.insert(Cow::Borrowed("entrypoint")); // Ensure entrypoint is exported

    println!("Exported symbols: {:?}", export_symbols);

    let mut linker = Linker::new(LinkerOptions {
        target: None,
        cpu: Cpu::V2, // Use BPF v2 instruction set
        cpu_features: String::new(),
        inputs: link_inputs,
        output: temp_output.clone(),
        output_type: OutputType::Object,
        libs: Vec::new(),
        optimize: OptLevel::No,
        export_symbols,
        unroll_loops: true,
        ignore_inline_never: false,
        dump_module: None,
        llvm_args: vec![format!("--bpf-stack-size={bpf_stack_size}")],
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
    //let _ = fs::remove_file(&temp_output);

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
