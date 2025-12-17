use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use sbpf_lld::full_link_program;

use clap::Parser;

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
}

fn split_inputs_output(files: Vec<PathBuf>, out: Option<PathBuf>) -> Result<(Vec<PathBuf>, PathBuf)> {
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
    let (input_paths, output_path) = split_inputs_output(cli.files, cli.out)?;

    println!("Number of input files: {}", input_paths.len());
    println!("Output file: {}", output_path.display());

    // Use complete version to process files
    let output_bytes = full_link_program(&input_paths)
        .context("Failed to link SBPF program")?;
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
