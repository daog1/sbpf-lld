# optest2.so Access Violation Analysis (0x1010101)

## Summary
The access violation at address `0x1010101` is not caused by a bad call relocation. It comes from the entrypoint passing a stack region filled with `0x01010101...` as the input pointer to `bytesEncodeB58`. Inside `bytesEncodeB58`, stack slots like `r10-0x60` are later loaded and used as pointers, which results in a write to `0x01010101`.

## Key Evidence
### 1) Entrypoint passes stack pointer as input
From `temp_linked.o` disassembly (same in `optest2.so` with `.text` base shift):
```
00000000000020a0 <entrypoint>:
  r1 = 0x101010101010101
  *(u64 *)(r10 - 0x48) = r1
  *(u64 *)(r10 - 0x50) = r1
  *(u64 *)(r10 - 0x58) = r1
  *(u64 *)(r10 - 0x60) = r1
  ...
  r1 = r10
  r1 += -0x60       ; r1 = r10-0x60
  r6 = r10
  r6 += -0x40       ; r6 = r10-0x40
  r2 = r6
  call bytesEncodeB58
```
This means `bytesEncodeB58` receives a pointer to stack memory that was just filled with `0x0101010101010101`.

### 2) bytesEncodeB58 expects a real input buffer
At `bytesEncodeB58` start:
```
0: r7 = r1
2: w5 = *(u8 *)(r7 + 0x1)
3: w3 = *(u8 *)(r7 + 0x0)
...
```
So `r1` must be a valid input buffer, not a dummy stack fill.

### 3) Later it dereferences stack slots as pointers
Example sequence in `optest2.so`:
```
0x1580: r6 = *(u64 *)(r10 - 0x60)
0x1588: *(u8 *)(r6 + 0x0) = ...
```
If `r10-0x60` contains `0x0101010101010101`, the store targets `0x01010101`, matching the observed error.

## Relocation / call target check
The entrypoint call target is correct; the apparent offset is just due to `.text` base shift:
- `.text` in `optest2.so` has `sh_addr = 0xE8`.
- `call -0x427` from entrypoint lands at `0xE8`, which is `.text` offset `0x0` (i.e., `bytesEncodeB58` start).
- So this is not a relocation bug.

## Conclusion
The crash is caused by entrypoint passing an uninitialized (or intentionally filled) stack pointer as input to `bytesEncodeB58`. The function later uses derived values from that stack area as pointers, leading to an access violation at `0x1010101`.

## Suggested next steps
- Compare entrypoint parameter setup between `optest.so` and `optest2.so`.
- Ensure entrypoint passes a valid input buffer to `bytesEncodeB58` (e.g., from Solana context / program input), not stack fill.
- If this is a test stub, adjust mollusk input or stub so `r1` points to real data.
