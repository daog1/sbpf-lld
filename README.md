# SBPF Linker (sbpf-lld)

A streamlined tool that relinks upstream BPF binaries into SBPF V0 compatible format for Solana programs.

## Core Advantages

Compared to the original complex sbpf-linker implementation, this project is significantly simplified:
- **95% code reduction**: Direct byte-level operations, avoiding complex AST parsing and reconstruction
- **Performance improvement**: Eliminates unnecessary intermediate conversion overhead
- **Strong maintainability**: Fewer dependencies, clear logic, easy to understand and maintain
- **High stability**: Reduces intermediate steps, lowers error probability

## How It Works

```
.o files → bpf-linker → byte-level relocations → .so output
```

1. **Input Processing**: Receives multiple BPF object files (.o)
2. **Initial Linking**: Uses bpf-linker to link multiple input files into a single object file
3. **Relocation Processing**: Applies SBPF-specific relocations directly at the byte level
4. **ELF Construction**: Generates final SBPF V0 compatible shared object (.so)

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


## Architecture Design

### Core Components

- **`RawSbpfData`**: Direct byte-level data extraction from ELF objects
- **`murmur3_32`**: Constant-time hash function for syscall relocations
- **`build_sbpf_so`**: ELF construction using object crate

### Key Technologies

1. **Byte-level Operations**: Avoids parse/rebuild cycles, directly modifies byte data
2. **Relocation Processing**:
   - Syscall relocations: Compute murmur3_32 hash
   - ROData relocations: Use symbol addresses
   - Other relocations: Use addend values
3. **ELF Construction**: Contains only necessary .text and .rodata sections

## Development Status

The project is ready for use and supports SVM ELF V0 format. Future versions will consider support for ELF V3 format.

The project is in implementation phase, progressing step by step based on `IMPLEMENTATION_PLAN.md`:

- ✅ Basic framework and data structures
- ✅ Section data extraction
- 🔄 Relocation processing (in progress)
- ⏳ ELF construction
- ⏳ Testing and verification

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
