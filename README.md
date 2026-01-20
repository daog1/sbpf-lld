# SBPF Linker (sbpf-lld)

A streamlined tool that relinks upstream BPF binaries into SBPF v2/v3 compatible format for Solana programs (v3 by default).

## Core Advantages

Compared to the original complex sbpf-linker implementation, this project is significantly simplified:
- **95% code reduction**: Direct byte-level operations, avoiding complex AST parsing and reconstruction
- **Performance improvement**: Eliminates unnecessary intermediate conversion overhead
- **Strong maintainability**: Fewer dependencies, clear logic, easy to understand and maintain
- **High stability**: Reduces intermediate steps, lowers error probability

## How It Works

```
.o files → bpf-linker → byte-level relocations → eBPF→sBPF conversion → v3 normalization → .so output
```

1. **Input Processing**: Receives multiple BPF object files (.o)
2. **Initial Linking**: Uses bpf-linker to link multiple input files into a single object file
3. **Relocation Processing**: Applies SBPF-specific relocations directly at the byte level
4. **eBPF to sBPF Conversion**: Converts eBPF instructions to sBPF v2 encoding when needed
5. **v3 Normalization**: Applies strict v3 requirements (static syscalls, function markers, return opcode)
6. **ELF Construction**: Generates final SBPF v2/v3 compatible shared object (.so)

## Installation

### Build from Source

```bash
git clone <repository-url>
cd sbpf-lld
cargo build --release
```

### Cargo Install

```bash
cargo install sbpf-lld
```

## Usage

### Basic Usage

```bash
sbpf-lld input1.o input2.o output.so
```

### With `-o/--out`

```bash
sbpf-lld -o output.so input1.o input2.o
sbpf-lld --out output.so input1.o input2.o
```

### Select SBPF Version (default: v3)

```bash
sbpf-lld --sbpf-version v3 input1.o input2.o output.so
sbpf-lld --sbpf-version v2 input1.o input2.o output.so
```

Note: v3 expects static syscalls (SYSCALL imm) and strict ELF headers. v2 keeps dynamic syscalls.

### SBPF v2 vs v3 behavior

- **Syscalls**: v2 uses dynamic syscall relocations; v3 uses static `SYSCALL imm` (murmur3 hash).
- **ELF headers**: v3 enforces strict PT_LOAD layout and fixed vaddrs (0, 1<<32, 2<<32, 3<<32).
- **Function markers**: v3 requires function start markers; CALL targets must land on a marker.
- **Return opcode**: v2 uses `EXIT` (0x95), v3 uses `RETURN` (0x9d).

### Environment Variables

- `SBPF_LLD_BPF_STACK_SIZE`: Set BPF stack size (default 4096 bytes, 4KiB)


## Architecture Design

### Core Components

- **`RawSbpfData`**: Direct byte-level data extraction from ELF objects
- **`murmur3_32`**: Constant-time hash function for syscall relocations
- **`convert_ebpf_to_sbpf_v2`**: Converts eBPF instructions to sBPF v2 encoding
- **`build_sbpf_so`**: ELF construction using object crate

### Key Technologies

1. **Byte-level Operations**: Avoids parse/rebuild cycles, directly modifies byte data
2. **Relocation Processing**:
    - Syscall relocations: Compute murmur3_32 hash
    - ROData relocations: Use symbol addresses
    - Other relocations: Use addend values
3. **eBPF to sBPF Conversion**: Complete conversion from eBPF instruction set to sBPF v2 format
4. **ELF Construction**: Contains only necessary .text and .rodata sections

## Development Status

The project supports SVM ELF v2 and v3 formats (v3 by default).

- ✅ Basic framework and data structures
- ✅ Section data extraction
- ✅ Relocation processing (completed)
- ✅ ELF construction (completed, v2/v3)
- ✅ Testing and verification (completed)
- ✅ eBPF to sBPF v2 instruction conversion (new)

## Technology Stack

- **Language**: Rust 2024 edition
- **Core Dependencies**:
  - `object`: ELF file parsing and construction
  - `bpf-linker`: Initial object file linking
  - `thiserror`: Error handling
- **Optional Features**:
  - `llvm-19/20/21`: LLVM version support
  - `rust-llvm-*`: Rust LLVM proxy integration

## Testing

The project adopts a unit testing strategy focused on core function verification:

```bash
cargo test
```

Test coverage includes:
- Section data extraction functionality
- Relocation application logic
- eBPF to sBPF instruction conversion
- ELF construction correctness
- Compatibility verification with existing .so files

## Development Commands

Use `justfile` for common development operations:

```bash
just ld      # Build and link test program
just read    # View ELF file structure
just run     # Run the generated program
```

## Contributing

Contributions are welcome! Please follow these principles:

1. **Test-Driven**: All new features must include corresponding unit tests
2. **Code Standards**: Follow standard Rust code style
3. **Documentation**: Update relevant documentation for new features

## License

This project uses dual licensing:
- Apache License 2.0
- MIT License

## Related Projects

- [Solana](https://github.com/solana-labs/solana): Solana blockchain platform
- [bpf-linker](https://github.com/solana-labs/bpf-linker): BPF linker tool
- [sbpf-linker](https://github.com/blueshift-gg/sbpf-linker): Reference SBPF linker implementation</content>
