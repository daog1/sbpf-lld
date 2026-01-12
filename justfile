ld:
    cargo build
    ./target/debug/sbpf-lld runtime.o test_debug3.so
ldvy:
    #!/usr/bin/env zsh
    # Ensure ml001 uses *this repo's* sbpf-lld, not a possibly stale cargo-installed one.
    cargo build
    repo_dir="$PWD"
    cd ../ml001
    PATH="$repo_dir/target/debug:$PATH" just vy inst_data.vy
    cp tests/inst_data.so ../sbpf-lld/
ld2:
    cargo build
    ./target/debug/sbpf-lld ryper_runtime.o /Users/ttt/code/vsrc/ryper/tests/context_methods_test.o test_debug3.so
read:
    ~/platform-tools-osx-aarch64/llvm/bin/llvm-readelf --all test_debug3.so
run:
    ../ryper/target/debug/ryper run-so -v test_debug3.so
run2:
    ../ryper/target/debug/ryper run-so -v b.so

ebpf:
    llc -march=bpfel -filetype=obj hello.ll -o hello.o
    llvm-objdump --disassemble --triple=bpfel hello.o
sbpf:
    ~/platform-tools-osx-aarch64/llvm/bin/llc -march=sbf -mcpu=v3 -filetype=obj hello.ll -o hellos.o
    ~/platform-tools-osx-aarch64/llvm/bin/llvm-objdump --disassemble hellos.o

ebpf_so:
    clang -target bpfel -c -fembed-bitcode -emit-llvm -o hello.bc hello.ll
    llc -march=bpfel -filetype=obj hello.bc -o hello.o
    ./target/debug/sbpf-lld hello.o hello.so
    ../ryper/target/debug/ryper run-so -v hello.so
dump_so:
    ~/platform-tools-osx-aarch64/llvm/bin/llvm-objdump --disassemble hello.so

ebpf_so2:
    #!/usr/bin/env zsh
    #~/platform-tools-osx-aarch64/llvm/bin/clang -target bpfel -c -fembed-bitcode -emit-llvm -o optest.bc optest.ll
    #llc -march=bpfel -filetype=obj optest.o -o optest.o
    SBPF_LLD_ENABLE_V2_CONVERSION=1 ./target/debug/sbpf-lld optest.bc optest2.so
    #export RUST_LOG=solana_runtime::message_processor=debug
    RUST_LOG=solana_runtime::message_processor=debug,solana_bpf_loader=debug,mollusk=debug ../ryper/target/debug/ryper run-so -v optest2.so
    #../ryper/target/debug/ryper run-so -v optest.so
ebpf_so3:
    #!/usr/bin/env zsh
    SBPF_LLD_V2_STAGE=3 ./target/debug/sbpf-lld optest2.bc optest3.so
    #export RUST_LOG=solana_runtime::message_processor=debug
    RUST_LOG=solana_runtime::message_processor=debug,solana_bpf_loader=debug,mollusk=debug ../ryper/target/debug/ryper run-so -v optest3.so
    #../ryper/target/debug/ryper run-so -v optest.so

sbpf2:
    ~/platform-tools-osx-aarch64/llvm/bin/clang -target bpf -c -fembed-bitcode -emit-llvm -o optest_sol.bc optest.bc
    ~/platform-tools-osx-aarch64/llvm/bin/llc -march=sbf -mcpu=v3 -filetype=obj optest_sol.bc -o hellos.o
    ~/platform-tools-osx-aarch64/llvm/bin/llvm-objdump --disassemble hellos.o
