use anyhow::{Context, Result};
use std::env;
use std::fs;
use std::path::PathBuf;
use sbpf_lld::full_link_program;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        anyhow::bail!("Usage: {} <input1.o> [input2.o ...] <output.so>", args[0]);
    }

    let output_path = &args[args.len() - 1];
    let input_paths: Vec<PathBuf> = args[1..args.len() - 1]
        .iter()
        .map(|s| PathBuf::from(s))
        .collect();

    println!("Number of input files: {}", input_paths.len());
    println!("Output file: {}", output_path);

    // Use complete version to process files
    let output_bytes = full_link_program(&input_paths)
        .context("Failed to link SBPF program")?;
    println!("Generated {} bytes of output", output_bytes.len());

    // Write output file
    fs::write(output_path, output_bytes)
        .with_context(|| format!("Failed to write output file: {}", output_path))?;

    println!("Successfully linked to {}", output_path);

    println!("Successfully linked to {}", output_path);
    Ok(())
}
