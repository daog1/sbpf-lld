use std::env;
use std::fs;
use std::path::PathBuf;

use sbpf_lld::{full_link_program, simple_link_program};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} <input1.o> [input2.o ...] <output.so>", args[0]);
        std::process::exit(1);
    }

    let output_path = &args[args.len() - 1];
    let input_paths: Vec<PathBuf> = args[1..args.len() - 1]
        .iter()
        .map(|s| PathBuf::from(s))
        .collect();

    println!("输入文件数量: {}", input_paths.len());
    println!("输出文件: {}", output_path);

    // 使用完整版本处理文件
    let output_bytes = full_link_program(&input_paths)?;
    println!("Generated {} bytes of output", output_bytes.len());

    // 写入输出文件
    fs::write(output_path, output_bytes)?;

    println!("Successfully linked to {}", output_path);
    Ok(())
}
