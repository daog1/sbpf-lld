use anyhow::{Context, Result};
use sbpf_lld::{LinkerConfig, full_link_program_with_options};
use std::fs;
use std::fs::OpenOptions;
use std::path::PathBuf;

use clap::{ArgAction, Parser, ValueEnum};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "sbpf-lld",
    about = "Link one or more SBPF .o files into a .so",
    disable_help_subcommand = true
)]
struct Cli {
    /// Output .so path (optional; if not provided, uses the last positional argument)
    #[arg(short = 'o', long = "out")]
    out: Option<PathBuf>,

    /// Input .o files (and optionally the output .so as the last positional argument)
    #[arg(required = true, num_args = 1..)]
    files: Vec<PathBuf>,

    /// LLVM target triple. When not provided, the target is inferred from the inputs
    #[arg(long)]
    target: Option<String>,

    /// Target BPF processor. Can be one of `generic`, `probe`, `v1`, `v2`, `v3`
    #[arg(long, default_value = "generic")]
    cpu: CpuArg,

    /// Enable or disable CPU features. For example: --cpu-features=+alu32,-dwarfris
    #[arg(long, value_name = "features", default_value = "")]
    cpu_features: String,

    /// Output type. Can be one of `llvm-bc`, `asm`, `llvm-ir`, `obj`
    #[arg(long, default_value = "obj")]
    emit: Vec<String>,

    /// Emit BTF information
    #[arg(long)]
    btf: bool,

    /// Permit automatic insertion of __bpf_trap calls
    #[arg(long)]
    allow_bpf_trap: bool,

    /// Add a directory to the library search path
    #[arg(short = 'L', num_args = 1)]
    libs: Vec<PathBuf>,

    /// Optimization level. 0-3, s, or z
    #[arg(short = 'O', default_value = "2")]
    optimize: Vec<String>,

    /// Export the symbols specified in the file `path`
    #[arg(long, value_name = "path")]
    export_symbols: Option<PathBuf>,

    /// Output logs to the given `path`
    #[arg(long, value_name = "path")]
    log_file: Option<PathBuf>,

    /// Set the log level. Can be one of `error`, `warn`, `info`, `debug`, `trace`
    #[arg(long, value_name = "level")]
    log_level: Option<String>,

    /// Try hard to unroll loops
    #[arg(long)]
    unroll_loops: bool,

    /// Ignore `noinline`/`#[inline(never)]`
    #[arg(long)]
    ignore_inline_never: bool,

    /// Dump the final IR module to the given `path` before generating the code
    #[arg(long, value_name = "path")]
    dump_module: Option<PathBuf>,

    /// Extra command line arguments to pass to LLVM
    #[arg(long, value_name = "args", use_value_delimiter = true, action = ArgAction::Append)]
    llvm_args: Vec<String>,

    /// Disable passing --bpf-expand-memcpy-in-order to LLVM
    #[arg(long)]
    disable_expand_memcpy_in_order: bool,

    /// Disable exporting memcpy/memmove/memset/memcmp/bcmp
    #[arg(long)]
    disable_memory_builtins: bool,

    /// Comma separated list of symbols to export
    #[arg(long, value_name = "symbols", use_value_delimiter = true, action = ArgAction::Append)]
    export: Vec<String>,

    /// Whether to treat LLVM errors as fatal
    #[arg(long, action = ArgAction::Set, default_value_t = true)]
    fatal_errors: bool,

    /// SBPF version for output
    #[arg(long = "sbpf-version", value_enum, default_value = "v3")]
    sbpf_version: SbpfVersionArg,

    /// Whether to enable debug output (compatibility)
    #[arg(long = "debug", hide = true)]
    _debug: bool,
}

#[derive(Clone, Debug, ValueEnum)]
enum SbpfVersionArg {
    V2,
    V3,
}

impl From<SbpfVersionArg> for sbpf_lld::SbpfVersion {
    fn from(value: SbpfVersionArg) -> Self {
        match value {
            SbpfVersionArg::V2 => sbpf_lld::SbpfVersion::V2,
            SbpfVersionArg::V3 => sbpf_lld::SbpfVersion::V3,
        }
    }
}

#[derive(Clone, Debug, ValueEnum)]
enum CpuArg {
    Generic,
    Probe,
    V1,
    V2,
    V3,
}

impl From<CpuArg> for bpf_linker::Cpu {
    fn from(value: CpuArg) -> Self {
        match value {
            CpuArg::Generic => bpf_linker::Cpu::Generic,
            CpuArg::Probe => bpf_linker::Cpu::Probe,
            CpuArg::V1 => bpf_linker::Cpu::V1,
            CpuArg::V2 => bpf_linker::Cpu::V2,
            CpuArg::V3 => bpf_linker::Cpu::V3,
        }
    }
}

fn parse_opt_level(values: &[String]) -> Result<bpf_linker::OptLevel> {
    let last = values.last().map(|v| v.as_str()).unwrap_or("2");
    Ok(match last {
        "0" => bpf_linker::OptLevel::No,
        "1" => bpf_linker::OptLevel::Less,
        "2" => bpf_linker::OptLevel::Default,
        "3" => bpf_linker::OptLevel::Aggressive,
        "s" | "S" => bpf_linker::OptLevel::Size,
        "z" | "Z" => bpf_linker::OptLevel::SizeMin,
        other => anyhow::bail!("Unsupported optimization level: {other}"),
    })
}

fn read_export_symbols(path: &PathBuf) -> Result<Vec<String>> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("Failed to read export symbols file: {}", path.display()))?;
    Ok(contents
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

fn build_env_filter(log_level: Option<&str>) -> Result<EnvFilter> {
    if let Some(level) = log_level {
        let level = level.to_ascii_lowercase();
        let directive = format!("{level},bpf_linker={level},sbpf_lld={level}");
        return EnvFilter::try_new(directive)
            .with_context(|| format!("Invalid log level: {level}"));
    }
    Ok(EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("error,bpf_linker=error,sbpf_lld=error")))
}

fn split_inputs_output(
    files: Vec<PathBuf>,
    out: Option<PathBuf>,
) -> Result<(Vec<PathBuf>, PathBuf)> {
    if let Some(out) = out {
        if files.is_empty() {
            anyhow::bail!("No input files provided");
        }
        return Ok((files, out));
    }

    if files.len() < 2 {
        anyhow::bail!("Usage: sbpf-lld <input1.o> [input2.o ...] <output.so>");
    }
    let mut inputs = files;
    let out = inputs.pop().expect("len checked");
    Ok((inputs, out))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let _log_guard = if let Some(path) = &cli.log_file {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create log directory: {}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("Failed to open log file: {}", path.display()))?;
        let (writer, guard) = tracing_appender::non_blocking(file);
        tracing_subscriber::fmt()
            .with_env_filter(build_env_filter(cli.log_level.as_deref())?)
            .with_writer(writer)
            .init();
        Some(guard)
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(build_env_filter(cli.log_level.as_deref())?)
            .with_writer(std::io::stderr)
            .init();
        None
    };

    let (input_paths, output_path) = split_inputs_output(cli.files, cli.out)?;

    println!("Number of input files: {}", input_paths.len());
    println!("Output file: {}", output_path.display());

    let mut export_symbols = Vec::new();
    if let Some(path) = &cli.export_symbols {
        export_symbols.extend(read_export_symbols(path)?);
    }
    export_symbols.extend(cli.export.clone());

    let linker_config = LinkerConfig {
        target: cli.target.clone(),
        cpu: cli.cpu.into(),
        cpu_features: cli.cpu_features.clone(),
        libs: cli.libs.clone(),
        optimize: parse_opt_level(&cli.optimize)?,
        export_symbols,
        unroll_loops: cli.unroll_loops,
        ignore_inline_never: cli.ignore_inline_never,
        dump_module: cli.dump_module.clone(),
        llvm_args: cli.llvm_args.clone(),
        disable_expand_memcpy_in_order: cli.disable_expand_memcpy_in_order,
        disable_memory_builtins: cli.disable_memory_builtins,
        btf: cli.btf,
        allow_bpf_trap: cli.allow_bpf_trap,
    };

    info!("Starting link, output={}", output_path.display());
    let output_bytes = match full_link_program_with_options(
        &input_paths,
        cli.sbpf_version.into(),
        &linker_config,
    ) {
        Ok(bytes) => bytes,
        Err(err) => {
            error!(error = %err, "sbpf-lld failed");
            return Err(err).context("Failed to link SBPF program");
        }
    };
    println!("Generated {} bytes of output", output_bytes.len());

    // Write output file
    fs::write(&output_path, output_bytes)
        .with_context(|| format!("Failed to write output file: {}", output_path.display()))?;

    println!("Successfully linked to {}", output_path.display());
    println!("Successfully linked to {}", output_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_positional_output() {
        let cli = Cli::try_parse_from(["sbpf-lld", "a.o", "b.o", "out.so"]).unwrap();
        let (inputs, out) = split_inputs_output(cli.files, cli.out).unwrap();
        assert_eq!(inputs, vec![PathBuf::from("a.o"), PathBuf::from("b.o")]);
        assert_eq!(out, PathBuf::from("out.so"));
    }

    #[test]
    fn parses_dash_o_output() {
        let cli = Cli::try_parse_from(["sbpf-lld", "-o", "out.so", "a.o"]).unwrap();
        let (inputs, out) = split_inputs_output(cli.files, cli.out).unwrap();
        assert_eq!(inputs, vec![PathBuf::from("a.o")]);
        assert_eq!(out, PathBuf::from("out.so"));
    }

    #[test]
    fn parses_out_eq_output() {
        let cli = Cli::try_parse_from(["sbpf-lld", "--out=out.so", "a.o"]).unwrap();
        let (inputs, out) = split_inputs_output(cli.files, cli.out).unwrap();
        assert_eq!(inputs, vec![PathBuf::from("a.o")]);
        assert_eq!(out, PathBuf::from("out.so"));
    }

    #[test]
    fn parses_dash_o_after_inputs() {
        let cli = Cli::try_parse_from(["sbpf-lld", "a.o", "b.o", "-o", "out.so"]).unwrap();
        let (inputs, out) = split_inputs_output(cli.files, cli.out).unwrap();
        assert_eq!(inputs, vec![PathBuf::from("a.o"), PathBuf::from("b.o")]);
        assert_eq!(out, PathBuf::from("out.so"));
    }
}
