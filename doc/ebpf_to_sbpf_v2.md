# eBPF to sBPF v2 Conversion Notes

This document summarizes a practical mapping from common LLVM eBPF
(bpfel-unknown-none) output to Solana sBPF v2, based on the local
documentation in doc/bytecode.md, doc/relocations.md, and doc/syscalls.md.

Scope
-----
- Input: "default" LLVM eBPF output (no custom extensions).
- Target: sBPF v2 (not v3).
- Goal: enable sbpf-lld to link bpfel-unknown-none objects into sBPF v2.

Key Differences (eBPF vs sBPF v2)
--------------------------------
- Opcode space: sBPF v2 repurposes several opcodes for load/store, so
  eBPF opcodes cannot be passed through directly; re-encode by semantic.
- 32-bit semantics: some ALU32 ops differ in sign/zero extension rules in v2.
- Extra arithmetic: sBPF v2 defines uhmul/udiv/urem/lmul/shmul/hor64.
- Syscalls: sBPF v2 uses murmur32(name) hashed call immediates via
  R_BPF_64_32 relocations.
- Relocations: sBPF v2 uses R_BPF_64_64 and R_BPF_64_RELATIVE for address
  fixups in text/rodata.

Instruction Mapping (Semantic)
------------------------------
The mapping below is semantic, not opcode-to-opcode. The eBPF instruction
must be decoded and then re-encoded as sBPF v2.

ALU64 / MOV64
- add64/sub64/mul64: map 1:1 to sBPF v2 add64/sub64/mul64.
- div64/mod64: map to udiv64/urem64 (v2-specific).
- or64/and64/xor64: map 1:1.
- lsh64/rsh64/arsh64: map to lsh64/rsh64/ash64.
- mov64: map 1:1.
- neg64: map to neg64 (still present in v2).

ALU32 / MOV32 (watch 32-bit semantics)
- add32/sub32/or32/and32/xor32/lsh32/rsh32/arsh32: map to sBPF v2 ALU32,
  but ensure v2 sign/zero extension rules match (see doc/bytecode.md).
- mul32: map to lmul32 (v2-specific).
- div32/mod32: map to udiv32/urem32 (v2-specific).
- mov32: map to v2 mov32 and apply v2 sign/zero extension rules.
- neg32: v2 reserves neg32; lower to a safe sequence (e.g., 0 - dst with
  32-bit semantics).

Load / Store
- ldx/stx/st (byte/half/word/dword): re-encode as sBPF v2 load/store
  opcodes. Do not pass through eBPF opcodes because v2 reuses opcode slots.

Jumps
- ja/jeq/jne/jgt/jge/jlt/jle/jset: map 1:1.
- jsgt/jsge/jslt/jsle: map 1:1.
- Offsets are relative to PC in instruction slots; keep slot-accurate offsets.

Call / Exit
- call imm:
  - helper/syscall: map to sBPF v2 call with imm = murmur32(syscall_name)
    written via R_BPF_64_32 relocation.
  - internal call: also call imm; avoid conflicts with syscall hashes.
- exit: map 1:1.

LDDW / Address Fixups
- lddw imm64: map 1:1.
- If imm64 is a text/rodata address, use R_BPF_64_64 or R_BPF_64_RELATIVE
  as required (see doc/relocations.md).

Relocations (v2)
----------------
- R_BPF_64_64: same-section fixups (text/rodata).
- R_BPF_64_RELATIVE: cross-section fixups.
- R_BPF_64_32: syscall hash relocation for external calls.

Notes / Open Points
-------------------
- "Default" eBPF does not have direct equivalents for sBPF v2-only ops.
  The mapping above only uses v2 extras when needed for ALU32 div/mod/mul.
- Internal calls vs syscalls can conflict in v2. Prefer relocations for syscalls.
- A precise helper-id -> syscall-name map is required for call lowering.

References
----------
- doc/bytecode.md
- doc/relocations.md
- doc/syscalls.md
