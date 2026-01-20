## v2 to v1 Instruction Conversion Plan (optest_sol.o as baseline)

Baseline: `optest_sol.o` uses sBPF v1 / eBPF-compatible opcodes (e.g. ldxb=0x71, stb=0x72,
stdw=0x7a, stxdw=0x7b, ldxdw=0x79). To match this baseline, v2-only opcodes must be
converted back to their v1 equivalents.

### Loads
- `0x8c` -> `0x61` (ldxw)
- `0x3c` -> `0x69` (ldxh)
- `0x2c` -> `0x71` (ldxb)
- `0x9c` -> `0x79` (ldxdw)

### Stores (immediate)
- `0x87` -> `0x62` (stw)
- `0x37` -> `0x6a` (sth)
- `0x27` -> `0x72` (stb)
- `0x97` -> `0x7a` (stdw)

### Stores (register)
- `0x8f` -> `0x63` (stxw)
- `0x3f` -> `0x6b` (stxh)
- `0x2f` -> `0x73` (stxb)
- `0x9f` -> `0x7b` (stxdw)

### ALU32 mul/div/mod (v2 product/quotient/remainder encodings)
- `0x86` -> `0x24` (mul32 imm)
- `0x8e` -> `0x2c` (mul32 reg)
- `0x46` -> `0x34` (div32 imm)
- `0x4e` -> `0x3c` (div32 reg)
- `0x66` -> `0x94` (mod32 imm)
- `0x6e` -> `0x9c` (mod32 reg)

### BPF_END (0xd4)
Keep `0xd4` for v1. Do not lower to `0xdc` or AND/MOV sequences.

### Notes
- If any v2 opcodes above appear in the output, they should be converted back to v1 to
  match `optest_sol.o`.
- This is a v2->v1 rollback only. It does not attempt to re-lower v2-only semantics that
  have no v1 equivalent (e.g. v2-only mul/div variants beyond the ALU32 subset above).
