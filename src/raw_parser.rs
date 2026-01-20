use anyhow::{Context, Result};
use object::ObjectSection;
use object::{Object as _, ObjectSymbol as _}; // Import Object and ObjectSymbol traits
use std::collections::HashMap;

use crate::murmur3::murmur3_32;
use crate::SbpfVersion;
use anyhow::bail;

const SBPF_SYSCALL_OPCODE: u8 = 0x95;
const SBPF_RETURN_OPCODE: u8 = 0x9d;

/// List of registered Solana SBPF system calls
/// These syscalls need to be converted to murmur3_32 hash values during relocation
pub const REGISTERED_SYSCALLS: &[&str] = &[
    "abort",
    "sol_panic_",
    "sol_log_",
    "sol_log_64_",
    "sol_log_compute_units_",
    "sol_log_pubkey",
    "sol_create_program_address",
    "sol_try_find_program_address",
    "sol_sha256",
    "sol_keccak256",
    "sol_secp256k1_recover",
    "sol_blake3",
    "sol_curve_validate_point",
    "sol_curve_group_op",
    "sol_get_clock_sysvar",
    "sol_get_epoch_schedule_sysvar",
    "sol_get_fees_sysvar",
    "sol_get_rent_sysvar",
    "sol_memcpy_",
    "sol_memmove_",
    "sol_memcmp_",
    "sol_memset_",
    "sol_invoke_signed_c",
    "sol_invoke_signed_rust",
    "sol_alloc_free_",
    "sol_set_return_data",
    "sol_get_return_data",
    "sol_log_data",
    "sol_get_processed_sibling_instruction",
    "sol_get_stack_height",
];

/// Raw SBPF data structure
/// Complete data extraction based on original byteparser.rs
#[derive(Debug)]
pub struct RawSbpfData {
    pub text_bytes: Vec<u8>,                  // .text section raw bytes
    pub rodata_bytes: Vec<u8>,                // .rodata section raw bytes
    pub symbols: HashMap<String, u64>,        // .text symbol name -> address
    pub function_symbols: Vec<u64>,           // function entry addresses
    pub rodata_symbols: HashMap<String, u64>, // .rodata symbol name -> offset within section
    pub relocations: Vec<RawRelocation>,      // complete relocation information
    pub entry_address: u64,
    pub sbpf_version: SbpfVersion,
}

/// Relocation information (based on original byteparser.rs processing logic)
#[derive(Debug, Clone)]
pub struct RawRelocation {
    pub offset: u64, // offset in .text
    pub symbol_name: String,
    pub symbol_address: u64,
    pub is_syscall: bool,  // whether it's a syscall in REGISTERED_SYSCALLS
    pub is_core_lib: bool, // whether it's a Rust core library symbol (starts with _ZN4core)
    pub addend: i64,       // addend value
    pub is_text_section: bool,
    pub is_rodata_section: bool,
    pub target_section_base: Option<u64>,
}

#[derive(thiserror::Error, Debug)]
pub enum RawSbpfError {
    #[error("Object file error: {0}")]
    ObjectFile(#[from] object::Error),
    #[error("ELF write error: {0}")]
    ElfWriteError(#[from] object::write::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Unsupported relocation at offset {offset:#x} for symbol '{symbol}'")]
    UnsupportedRelocation { offset: u64, symbol: String },
    #[error("Symbol '{symbol}' not found")]
    SymbolNotFound { symbol: String },
}

impl RawSbpfData {
    pub fn new() -> Self {
        Self::new_with_version(SbpfVersion::V2)
    }

    pub fn new_with_version(sbpf_version: SbpfVersion) -> Self {
        Self {
            text_bytes: Vec::new(),
            rodata_bytes: Vec::new(),
            symbols: HashMap::new(),
            function_symbols: Vec::new(),
            rodata_symbols: HashMap::new(),
            relocations: Vec::new(),
            entry_address: 0,
            sbpf_version,
        }
    }

    /// Extract raw SBPF data from object file
    pub fn from_object_file(bytes: &[u8], sbpf_version: SbpfVersion) -> Result<Self> {
        let obj = object::File::parse(bytes).context("Failed to parse object file")?;
        let mut result = Self::new_with_version(sbpf_version);

        // Extract .text* sections and build section base offsets
        let text_section_bases = result
            .extract_text_section(&obj)
            .context("Failed to extract .text sections")?;

        // Extract symbol table (adjusted for concatenated .text*)
        result
            .extract_symbols(&obj, &text_section_bases)
            .context("Failed to extract symbol table")?;

        // Normalize to v1/eBPF first, then optionally upgrade to v2.
        // result
        //     .convert_ebpf_to_sbpf_v1()
        //     .context("Failed to convert sBPF v2 to v1")?;

        let enable_v2 = matches!(sbpf_version, SbpfVersion::V2 | SbpfVersion::V3);
        /* std::env::var("SBPF_LLD_ENABLE_V2_CONVERSION")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);*/
        if enable_v2 {
            result
                .convert_ebpf_to_sbpf_v2()
                .context("Failed to convert eBPF to sBPF v2")?;
        }

        result.sbpf_version = sbpf_version;
        // Extract .rodata section
        result
            .extract_rodata_section(&obj)
            .context("Failed to extract .rodata section")?;

        // Extract relocation information (adjusted for concatenated .text*)
        result
            .extract_relocations(&obj, &text_section_bases)
            .context("Failed to extract relocations")?;

        Ok(result)
    }

    /// Extract symbol table
    fn extract_symbols(
        &mut self,
        obj: &object::File,
        text_section_bases: &HashMap<object::SectionIndex, u64>,
    ) -> Result<()> {
        fn is_function_symbol(symbol: &object::Symbol) -> bool {
            if symbol.kind() != object::SymbolKind::Text || !symbol.is_definition() {
                return false;
            }
            match symbol.flags() {
                object::SymbolFlags::Elf { st_info, .. } => {
                    (st_info & 0x0f) == object::elf::STT_FUNC
                }
                _ => true,
            }
        }

        for symbol in obj.symbols() {
            if symbol.kind() == object::SymbolKind::Text && symbol.is_definition() {
                if let Ok(name) = symbol.name() {
                    let mut addr = symbol.address();
                    if let Some(section_idx) = symbol.section_index() {
                        if let Some(base) = text_section_bases.get(&section_idx) {
                            addr = base + addr;
                        }
                    }
                    self.symbols.insert(name.to_string(), addr);
                    if name == "entrypoint" {
                        self.entry_address = addr;
                        eprintln!("entrypoint: 0x{:0x}", self.entry_address);
                    }
                    if is_function_symbol(&symbol) {
                        self.function_symbols.push(addr);
                        eprintln!("add function: {} 0x{:0x}", name, addr);
                    }
                }
            } else if let Some(section_idx) = symbol.section_index() {
                if let Ok(section) = obj.section_by_index(section_idx) {
                    if section.name()?.starts_with(".rodata") {
                        if let Ok(name) = symbol.name() {
                            self.rodata_symbols
                                .insert(name.to_string(), symbol.address());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Extract .text section raw bytes
    fn extract_text_section(
        &mut self,
        obj: &object::File,
    ) -> Result<HashMap<object::SectionIndex, u64>> {
        let mut section_bases = HashMap::new();
        for section in obj.sections() {
            if let Ok(name) = section.name() {
                if !name.starts_with(".text") {
                    continue;
                }
                let data = section.data()?;
                let base = self.text_bytes.len() as u64;
                section_bases.insert(section.index(), base);
                self.text_bytes.extend_from_slice(data);
                println!(
                    "Extracted {}: {} bytes (base 0x{:x})",
                    name,
                    data.len(),
                    base
                );
            }
        }
        println!("Extracted .text* total: {} bytes", self.text_bytes.len());

        // Validate instruction integrity
        self.validate_text_instructions()?;
        Ok(section_bases)
    }

    fn insert_function_start_markers(&mut self) -> Result<()> {
        if !matches!(self.sbpf_version, SbpfVersion::V3) {
            return Ok(());
        }

        let mut function_addrs = Vec::new();
        function_addrs.push(0);
        if self.entry_address != 0 {
            function_addrs.push(self.entry_address);
        }
        function_addrs.extend(self.collect_call_targets());
        function_addrs.sort_unstable();
        function_addrs.dedup();

        if function_addrs.is_empty() {
            return Ok(());
        }

        let mut insert_points: Vec<u64> = Vec::new();
        for addr in &function_addrs {
            let addr_usize = *addr as usize;
            if addr_usize + 8 > self.text_bytes.len() {
                bail!("Function start out of bounds at {:#x}", addr);
            }
            if !Self::is_function_start_marker(&self.text_bytes[addr_usize..addr_usize + 8]) {
                insert_points.push(*addr);
            }
        }

        if insert_points.is_empty() {
            return Ok(());
        }

        insert_points.sort_unstable();
        insert_points.dedup();

        let mut function_pcs = std::collections::HashSet::new();
        for addr in &function_addrs {
            function_pcs.insert(addr / 8);
        }
        let call_patches = self.compute_call_patches(&insert_points, &function_pcs)?;

        for (idx, addr) in insert_points.iter().enumerate() {
            let insert_at = addr + (idx as u64 * 8);
            let insert_at = insert_at as usize;
            let marker = Self::function_start_marker_bytes();
            self.text_bytes
                .splice(insert_at..insert_at, marker.iter().copied());
        }

        let shift_before = |addr: u64| -> u64 {
            let count = insert_points.partition_point(|&point| point < addr);
            (count as u64) * 8
        };
        let shift_before_or_equal = |addr: u64| -> u64 {
            let count = insert_points.partition_point(|&point| point <= addr);
            (count as u64) * 8
        };

        self.entry_address = self.entry_address.saturating_add(shift_before(self.entry_address));

        for addr in self.symbols.values_mut() {
            *addr = addr.saturating_add(shift_before(*addr));
        }

        for reloc in self.relocations.iter_mut() {
            reloc.offset = reloc.offset.saturating_add(shift_before_or_equal(reloc.offset));
            if reloc.is_text_section {
                let Some(base) = reloc.target_section_base else {
                    continue;
                };
                if let Some(new_addr) = self.symbols.get(&reloc.symbol_name) {
                    if *new_addr >= base {
                        reloc.symbol_address = new_addr - base;
                    }
                }
            }
        }

        for (offset, imm) in call_patches {
            self.patch_immediate(offset, imm)?;
        }

        self.rewrite_external_calls_to_syscalls()?;
        self.rewrite_exit_to_return()?;

        Ok(())
    }

    fn collect_call_targets(&self) -> Vec<u64> {
        let mut targets = Vec::new();
        let text_len = self.text_bytes.len();
        for pc in (0..text_len).step_by(8) {
            if pc + 8 > text_len {
                break;
            }
            if self.text_bytes[pc] != 0x85 {
                continue;
            }
            let imm = i32::from_le_bytes(self.text_bytes[pc + 4..pc + 8].try_into().unwrap());
            let target_pc = (pc as i64 / 8).saturating_add(imm as i64).saturating_add(1);
            if target_pc < 0 || target_pc >= (text_len as i64 / 8) {
                continue;
            }
            targets.push((target_pc as u64) * 8);
        }
        targets
    }

    fn compute_call_patches(
        &self,
        insert_points: &[u64],
        function_pcs: &std::collections::HashSet<u64>,
    ) -> Result<Vec<(u64, i64)>> {
        if insert_points.is_empty() {
            return Ok(Vec::new());
        }

        let mut patches = Vec::new();
        let count_before_or_equal = |addr: u64| -> i64 {
            insert_points.partition_point(|&point| point <= addr) as i64
        };

        let text_len = self.text_bytes.len();
        for pc in (0..text_len).step_by(8) {
            if pc + 8 > text_len {
                break;
            }
            let opc = self.text_bytes[pc];
            if opc != 0x85 {
                continue;
            }
            let imm = i32::from_le_bytes(self.text_bytes[pc + 4..pc + 8].try_into().unwrap());
            let old_pc = (pc / 8) as i64;
            let target_pc_old = old_pc.saturating_add(imm as i64).saturating_add(1);
            if target_pc_old < 0 {
                continue;
            }
            if !function_pcs.contains(&(target_pc_old as u64)) {
                continue;
            }
            let old_pc_bytes = (old_pc as u64) * 8;
            let target_pc_old_bytes = (target_pc_old as u64) * 8;
            let new_pc =
                old_pc + count_before_or_equal(old_pc_bytes);
            let new_target_pc =
                target_pc_old + count_before_or_equal(target_pc_old_bytes);
            let new_imm = new_target_pc.saturating_sub(new_pc).saturating_sub(1);
            if new_imm < i32::MIN as i64 || new_imm > i32::MAX as i64 {
                bail!("Call immediate out of range after marker insertion");
            }
            let new_offset = (new_pc as u64) * 8;
            patches.push((new_offset, new_imm));
        }

        Ok(patches)
    }

    fn rewrite_external_calls_to_syscalls(&mut self) -> Result<()> {
        if !matches!(self.sbpf_version, SbpfVersion::V3) {
            return Ok(());
        }

        let text_len = self.text_bytes.len();
        let mut markers = std::collections::HashSet::new();
        for pc in (0..text_len).step_by(8) {
            if pc + 8 > text_len {
                break;
            }
            if Self::is_function_start_marker(&self.text_bytes[pc..pc + 8]) {
                markers.insert((pc / 8) as i64);
            }
        }

        for pc in (0..text_len).step_by(8) {
            if pc + 8 > text_len {
                break;
            }
            if self.text_bytes[pc] != 0x85 {
                continue;
            }
            let imm = i32::from_le_bytes(self.text_bytes[pc + 4..pc + 8].try_into().unwrap());
            let target_pc = (pc as i64 / 8).saturating_add(imm as i64).saturating_add(1);
            if !markers.contains(&target_pc) {
                self.text_bytes[pc] = SBPF_SYSCALL_OPCODE;
                self.text_bytes[pc + 1] = 0;
                self.text_bytes[pc + 2] = 0;
                self.text_bytes[pc + 3] = 0;
            }
        }

        Ok(())
    }

    fn rewrite_exit_to_return(&mut self) -> Result<()> {
        if !matches!(self.sbpf_version, SbpfVersion::V3) {
            return Ok(());
        }

        let text_len = self.text_bytes.len();
        for pc in (0..text_len).step_by(8) {
            if pc + 8 > text_len {
                break;
            }
            if self.text_bytes[pc] != SBPF_SYSCALL_OPCODE {
                continue;
            }
            let imm = i32::from_le_bytes(self.text_bytes[pc + 4..pc + 8].try_into().unwrap());
            if imm != 0 {
                continue;
            }
            self.text_bytes[pc] = SBPF_RETURN_OPCODE;
            self.text_bytes[pc + 1] = 0;
            self.text_bytes[pc + 2] = 0;
            self.text_bytes[pc + 3] = 0;
        }

        Ok(())
    }

    fn function_start_marker_bytes() -> [u8; 8] {
        // add64 r10, 0
        [0x07, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    }

    fn is_function_start_marker(bytes: &[u8]) -> bool {
        if bytes.len() < 8 {
            return false;
        }
        let opc = bytes[0];
        let dst = bytes[1] & 0x0f;
        opc == 0x07 && dst == 10
    }

    /// Convert eBPF instructions to sBPF v2 encoding in-place.
    fn convert_ebpf_to_sbpf_v2(&mut self) -> Result<()> {
        let stage = std::env::var("SBPF_LLD_V2_STAGE")
            .ok()
            .and_then(|v| v.parse::<u8>().ok())
            .unwrap_or(3)
            .min(3);
        let enable_stage1 = stage >= 1;
        let enable_stage2 = stage >= 2;
        let enable_stage3 = stage >= 3;

        let mut offset = 0usize;
        while offset < self.text_bytes.len() {
            if offset + 8 > self.text_bytes.len() {
                break;
            }

            let opcode = self.text_bytes[offset];
            if opcode == 0x18 {
                // LDDW occupies two slots. Lower to mov32 + hor64 for sBPF v2.
                if enable_stage1 {
                    let regs = self.text_bytes[offset + 1];
                    let dst = regs & 0x0f;
                    let imm_lo = i32::from_le_bytes(
                        self.text_bytes[offset + 4..offset + 8].try_into().unwrap(),
                    );
                    let imm_hi = i32::from_le_bytes(
                        self.text_bytes[offset + 12..offset + 16]
                            .try_into()
                            .unwrap(),
                    );

                    // mov32 dst, imm_lo
                    self.text_bytes[offset] = 0xb4;
                    self.text_bytes[offset + 1] = dst; // src=0
                    self.text_bytes[offset + 2..offset + 4].copy_from_slice(&0i16.to_le_bytes());
                    self.text_bytes[offset + 4..offset + 8].copy_from_slice(&imm_lo.to_le_bytes());

                    // hor64 dst, imm_hi
                    let second = offset + 8;
                    self.text_bytes[second] = 0xf7;
                    self.text_bytes[second + 1] = dst; // src=0
                    self.text_bytes[second + 2..second + 4].copy_from_slice(&0i16.to_le_bytes());
                    self.text_bytes[second + 4..second + 8].copy_from_slice(&imm_hi.to_le_bytes());
                }

                offset += 16;
                continue;
            }

            let regs = self.text_bytes[offset + 1];
            let dst = regs & 0x0f;
            let src = (regs >> 4) & 0x0f;
            let imm =
                i32::from_le_bytes(self.text_bytes[offset + 4..offset + 8].try_into().unwrap());

            let mut new_opcode = opcode;
            let mut new_regs = regs;
            let mut new_imm = imm;

            match opcode {
                // eBPF loads -> sBPF v2 loads
                0x61 if enable_stage1 => new_opcode = 0x8c, // ldxw
                0x69 if enable_stage1 => new_opcode = 0x3c, // ldxh
                0x71 if enable_stage1 => new_opcode = 0x2c, // ldxb
                0x79 if enable_stage1 => new_opcode = 0x9c, // ldxdw

                // eBPF stores (imm) -> sBPF v2 stores
                0x62 if enable_stage1 => new_opcode = 0x87, // stw
                0x6a if enable_stage1 => new_opcode = 0x37, // sth
                0x72 if enable_stage1 => new_opcode = 0x27, // stb
                0x7a if enable_stage1 => new_opcode = 0x97, // stdw

                // eBPF stores (reg) -> sBPF v2 stores
                0x63 if enable_stage1 => new_opcode = 0x8f, // stxw
                0x6b if enable_stage1 => new_opcode = 0x3f, // stxh
                0x73 if enable_stage1 => new_opcode = 0x2f, // stxb
                0x7b if enable_stage1 => new_opcode = 0x9f, // stxdw

                // eBPF ALU32 mul/div/mod -> sBPF v2 product/quotient/remainder
                0x24 if enable_stage3 => new_opcode = 0x86, // lmul32 imm
                0x2c if enable_stage3 => new_opcode = 0x8e, // lmul32 reg
                0x34 if enable_stage3 => new_opcode = 0x46, // udiv32 imm
                0x3c if enable_stage3 => new_opcode = 0x4e, // udiv32 reg
                0x94 if enable_stage3 => new_opcode = 0x66, // urem32 imm
                0x9c if enable_stage3 => new_opcode = 0x6e, // urem32 reg
                // eBPF ALU64 mul/div/mod -> sBPF v2 lmul/udiv/urem
                0x27 if enable_stage2 => new_opcode = 0x96, // lmul64 imm
                0x2f if enable_stage2 => new_opcode = 0x9e, // lmul64 reg
                0x37 if enable_stage2 => new_opcode = 0x56, // udiv64 imm
                0x3f if enable_stage2 => new_opcode = 0x5e, // udiv64 reg
                0x97 if enable_stage2 => new_opcode = 0x76, // urem64 imm
                0x9f if enable_stage2 => new_opcode = 0x7e, // urem64 reg

                // eBPF BPF_END (opcode 0xD4) -> sBPF v2 be/and/mov
                0xd4 if enable_stage3 => {
                    if src == 1 {
                        // BPF_TO_BE => sBPF be
                        new_opcode = 0xdc;
                        new_regs = dst; // src=0
                    } else {
                        // BPF_TO_LE => lower to AND32 or MOV64
                        match imm {
                            16 => {
                                new_opcode = 0x54; // and32 imm
                                new_regs = dst; // src=0
                                new_imm = 0x0000ffff;
                            }
                            32 => {
                                new_opcode = 0x54; // and32 imm
                                new_regs = dst; // src=0
                                new_imm = 0xffff_ffffu32 as i32;
                            }
                            64 => {
                                new_opcode = 0xbf; // mov64 reg
                                new_regs = dst | (dst << 4);
                                new_imm = 0;
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }

            if new_opcode != opcode {
                self.text_bytes[offset] = new_opcode;
            }
            if new_regs != regs {
                self.text_bytes[offset + 1] = new_regs;
            }
            if new_imm != imm {
                self.text_bytes[offset + 4..offset + 8].copy_from_slice(&new_imm.to_le_bytes());
            }

            offset += 8;
        }
        Ok(())
    }

    /// Convert sBPF v2 opcodes back to eBPF/v1 encoding in-place.
    fn convert_ebpf_to_sbpf_v1(&mut self) -> Result<()> {
        let mut offset = 0usize;
        while offset < self.text_bytes.len() {
            if offset + 8 > self.text_bytes.len() {
                break;
            }

            let opcode = self.text_bytes[offset];
            if opcode == 0x18 {
                // LDDW occupies two slots.
                offset += 16;
                continue;
            }

            let regs = self.text_bytes[offset + 1];
            let imm =
                i32::from_le_bytes(self.text_bytes[offset + 4..offset + 8].try_into().unwrap());

            let mut new_opcode = opcode;
            let mut new_regs = regs;
            let mut new_imm = imm;

            match opcode {
                // v2 loads -> eBPF loads
                0x8c => new_opcode = 0x61, // ldxw
                0x3c => new_opcode = 0x69, // ldxh
                0x2c => new_opcode = 0x71, // ldxb
                0x9c => new_opcode = 0x79, // ldxdw

                // v2 stores (imm) -> eBPF stores
                0x87 => new_opcode = 0x62, // stw
                0x37 => new_opcode = 0x6a, // sth
                0x27 => new_opcode = 0x72, // stb
                0x97 => new_opcode = 0x7a, // stdw

                // v2 stores (reg) -> eBPF stores
                0x8f => new_opcode = 0x63, // stxw
                0x3f => new_opcode = 0x6b, // stxh
                0x2f => new_opcode = 0x73, // stxb
                0x9f => new_opcode = 0x7b, // stxdw

                // v2 ALU32 product/quotient/remainder -> eBPF ALU32 mul/div/mod
                0x86 => new_opcode = 0x24, // mul32 imm
                0x8e => new_opcode = 0x2c, // mul32 reg
                0x46 => new_opcode = 0x34, // div32 imm
                0x4e => new_opcode = 0x3c, // div32 reg
                0x66 => new_opcode = 0x94, // mod32 imm
                0x6e => new_opcode = 0x9c, // mod32 reg

                // v2 BPF_END replacements -> v1 BPF_END
                0xdc => {
                    // be -> end-to-be
                    new_opcode = 0xd4;
                    new_regs = (regs & 0x0f) | (1 << 4);
                }
                0x54 => {
                    if imm == 0x0000ffff || imm == -1 {
                        new_opcode = 0xd4;
                        new_regs = regs & 0x0f; // src=0 (to_le)
                        new_imm = if imm == 0x0000ffff { 16 } else { 32 };
                    }
                }
                0xbf => {
                    if (regs & 0x0f) == (regs >> 4) && imm == 0 {
                        new_opcode = 0xd4;
                        new_regs = regs & 0x0f; // src=0 (to_le)
                        new_imm = 64;
                    }
                }
                _ => {}
            }

            if new_opcode != opcode {
                self.text_bytes[offset] = new_opcode;
            }
            if new_regs != regs {
                self.text_bytes[offset + 1] = new_regs;
            }
            if new_imm != imm {
                self.text_bytes[offset + 4..offset + 8].copy_from_slice(&new_imm.to_le_bytes());
            }

            offset += 8;
        }
        Ok(())
    }

    /// Validate instruction integrity in .text section
    fn validate_text_instructions(&self) -> Result<()> {
        let mut offset = 0;
        let mut instruction_count = 0;

        while offset < self.text_bytes.len() {
            if offset + 8 > self.text_bytes.len() {
                println!(
                    "Warning: .text section incomplete at offset 0x{:x}, {} bytes remaining",
                    offset,
                    self.text_bytes.len() - offset
                );
                break;
            }

            // Check if it's a double-word instruction (LDDW)
            // LDDW instruction format: opcode=0x18, imm=0, src=0
            let opcode = self.text_bytes[offset];
            let inst_len = if opcode == 0x18 { 16 } else { 8 };

            if offset + inst_len > self.text_bytes.len() {
                println!(
                    "Warning: instruction incomplete at offset 0x{:x}, needs {} bytes, {} bytes remaining",
                    offset,
                    inst_len,
                    self.text_bytes.len() - offset
                );
                break;
            }

            offset += inst_len;
            instruction_count += 1;
        }

        println!(
            "Validation result: {} instructions, total size {} bytes",
            instruction_count,
            self.text_bytes.len()
        );
        Ok(())
    }

    /// Extract .rodata section
    fn extract_rodata_section(&mut self, obj: &object::File) -> Result<()> {
        for section in obj.sections() {
            if section.name()?.starts_with(".rodata") {
                self.rodata_bytes.extend_from_slice(section.data()?);
            }
        }
        Ok(())
    }

    /// Extract relocation information
    fn extract_relocations(
        &mut self,
        obj: &object::File,
        text_section_bases: &HashMap<object::SectionIndex, u64>,
    ) -> Result<()> {
        let is_rodata_name = |name: &str| {
            name.starts_with(".rodata")
                || name.starts_with(".data.rel.ro")
                || name.starts_with(".eh_frame")
        };
        for section in obj.sections() {
            let Ok(name) = section.name() else { continue };
            if !name.starts_with(".text") {
                continue;
            }
            let base = text_section_bases
                .get(&section.index())
                .copied()
                .unwrap_or(0);
            for (offset, rel) in section.relocations() {
                match rel.target() {
                    object::RelocationTarget::Symbol(sym_idx) => {
                        if let Some(symbol) = obj.symbol_by_index(sym_idx).ok() {
                            let symbol_name_str = symbol.name().unwrap_or_default().to_string();
                            let is_syscall =
                                REGISTERED_SYSCALLS.contains(&symbol_name_str.as_str());
                            let is_core_lib = symbol_name_str.starts_with("_ZN4core");
                            let (is_text_section, is_rodata_section, target_section_base) =
                                match symbol.section_index() {
                                    Some(section_idx) => {
                                        if let Ok(section) = obj.section_by_index(section_idx) {
                                            let name = section.name().unwrap_or_default();
                                            let is_text = name.starts_with(".text");
                                            let is_rodata = is_rodata_name(name);
                                            let base = if is_text {
                                                text_section_bases.get(&section_idx).copied()
                                            } else {
                                                None
                                            };
                                            (is_text, is_rodata, base)
                                        } else {
                                            (false, false, None)
                                        }
                                    }
                                    None => (false, false, None),
                                };
                            eprintln!("RelocationTarget {}", symbol_name_str);
                            self.relocations.push(RawRelocation {
                                offset: base + offset,
                                symbol_name: symbol_name_str,
                                symbol_address: symbol.address(),
                                is_syscall,
                                is_core_lib,
                                addend: rel.addend(),
                                is_text_section,
                                is_rodata_section,
                                target_section_base,
                            });
                        }
                    }
                    object::RelocationTarget::Section(section_idx) => {
                        let (is_text_section, is_rodata_section, target_section_base) =
                            if let Ok(section) = obj.section_by_index(section_idx) {
                                let name = section.name().unwrap_or_default();
                                let is_text = name.starts_with(".text");
                                let is_rodata = is_rodata_name(name);
                                let base = if is_text {
                                    text_section_bases.get(&section_idx).copied()
                                } else {
                                    None
                                };
                                (is_text, is_rodata, base)
                            } else {
                                (false, false, None)
                            };
                        self.relocations.push(RawRelocation {
                            offset: base + offset,
                            symbol_name: String::new(),
                            symbol_address: 0,
                            is_syscall: false,
                            is_core_lib: false,
                            addend: rel.addend(),
                            is_text_section,
                            is_rodata_section,
                            target_section_base,
                        });
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Apply relocations
    pub fn apply_relocations(&mut self) -> Result<()> {
        println!(
            "Before applying relocations: .text section size = {}",
            self.text_bytes.len()
        );

        // Collect all relocations to apply first to avoid borrow conflicts
        let relocations: Vec<RawRelocation> = self.relocations.iter().cloned().collect();
        println!("Need to apply {} relocations", relocations.len());

        for reloc in relocations {
            println!(
                "Applying relocation: offset=0x{:x}, symbol={}, is_syscall={}, is_core_lib={}",
                reloc.offset, reloc.symbol_name, reloc.is_syscall, reloc.is_core_lib
            );
            self.apply_relocation(&reloc)?;
        }

        println!(
            "After applying relocations: .text section size = {}",
            self.text_bytes.len()
        );
        self.insert_function_start_markers()
            .context("Failed to insert function start markers")?;
        Ok(())
    }

    /// Apply single relocation (based on original byteparser.rs logic)
    fn apply_relocation(&mut self, reloc: &RawRelocation) -> Result<()> {
        if reloc.is_syscall {
            if matches!(self.sbpf_version, SbpfVersion::V3) {
                let hash = murmur3_32(reloc.symbol_name.as_bytes());
                self.patch_syscall(reloc.offset, hash as i64)?;
            } else {
                // v0/v2 format: keep placeholder, let .rel.dyn patch
                self.patch_immediate(reloc.offset, -1)?;
            }
            return Ok(());
        }
        if reloc.is_text_section {
            let Some(base) = reloc.target_section_base else {
                anyhow::bail!(
                    "Missing .text section base for relocation at {:#x}",
                    reloc.offset
                );
            };
            let addend = if reloc.addend > 0 {
                reloc.addend as u64
            } else {
                0
            };
            let target_addr = base + reloc.symbol_address + addend;
            let next_pc = reloc.offset + 8;
            let delta = target_addr as i64 - next_pc as i64;
            if delta % 8 != 0 {
                anyhow::bail!(
                    "Unaligned text relocation at {:#x}: delta={}",
                    reloc.offset,
                    delta
                );
            }
            self.patch_immediate(reloc.offset, delta / 8)?;
            return Ok(());
        }
        // Non-syscall, non-text: keep immediate for rodata addends
        if !reloc.is_rodata_section {
            self.patch_immediate(reloc.offset, 0)?;
        }
        Ok(())
    }

    fn patch_syscall(&mut self, offset: u64, imm: i64) -> Result<()> {
        let opcode_offset = offset as usize;
        if opcode_offset + 8 > self.text_bytes.len() {
            anyhow::bail!("Syscall instruction out of bounds at offset {:#x}", offset);
        }
        self.text_bytes[opcode_offset] = SBPF_SYSCALL_OPCODE;
        self.text_bytes[opcode_offset + 1] = 0;
        self.text_bytes[opcode_offset + 2] = 0;
        self.text_bytes[opcode_offset + 3] = 0;
        self.patch_immediate(offset, imm)?;
        Ok(())
    }

    // No-op placeholder removed; syscall rewrite now happens after marker insertion.

    /// Patch immediate field
    fn patch_immediate(&mut self, offset: u64, value: i64) -> Result<()> {
        // BPF instruction format: opcode(1) + regs(1) + offset(2) + immediate(4)
        // immediate field stored in little-endian, 32-bit

        let imm_offset = offset as usize + 4;

        // Check bounds
        if imm_offset + 4 > self.text_bytes.len() {
            anyhow::bail!("Relocation out of bounds at offset {:#x}", offset);
        }

        // Convert i64 to i32 (BPF immediate is 32-bit), then to bytes
        let imm_value = value as i32;
        let bytes = imm_value.to_le_bytes();
        self.text_bytes[imm_offset..imm_offset + 4].copy_from_slice(&bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inst(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0] = opcode;
        bytes[1] = (dst & 0x0f) | ((src & 0x0f) << 4);
        bytes[2..4].copy_from_slice(&off.to_le_bytes());
        bytes[4..8].copy_from_slice(&imm.to_le_bytes());
        bytes
    }

    #[test]
    fn test_raw_sbpf_data_new() {
        let data = RawSbpfData::new();
        assert!(data.text_bytes.is_empty());
        assert!(data.rodata_bytes.is_empty());
        assert!(data.symbols.is_empty());
        assert!(data.relocations.is_empty());
        assert_eq!(data.entry_address, 0);
        assert_eq!(data.sbpf_version, SbpfVersion::V2);
    }

    #[test]
    fn test_convert_ebpf_to_sbpf_v2_opcodes() {
        let mut data = RawSbpfData::new();
        data.text_bytes.extend_from_slice(&inst(0x61, 1, 2, 0, 0)); // ldxw
        data.text_bytes.extend_from_slice(&inst(0x62, 1, 0, 0, 1)); // stw imm
        data.text_bytes.extend_from_slice(&inst(0x63, 1, 2, 0, 0)); // stxw
        data.text_bytes.extend_from_slice(&inst(0x24, 1, 0, 0, 2)); // mul32 imm
        data.text_bytes.extend_from_slice(&inst(0x2c, 1, 2, 0, 0)); // mul32 reg
        data.text_bytes.extend_from_slice(&inst(0x34, 1, 0, 0, 3)); // div32 imm
        data.text_bytes.extend_from_slice(&inst(0x3c, 1, 2, 0, 0)); // div32 reg
        data.text_bytes.extend_from_slice(&inst(0x94, 1, 0, 0, 5)); // mod32 imm
        data.text_bytes.extend_from_slice(&inst(0x9c, 1, 2, 0, 0)); // mod32 reg

        data.convert_ebpf_to_sbpf_v2().unwrap();

        let opcodes: Vec<u8> = data.text_bytes.iter().step_by(8).cloned().collect();
        assert_eq!(
            opcodes,
            vec![0x8c, 0x87, 0x8f, 0x86, 0x8e, 0x46, 0x4e, 0x66, 0x6e]
        );
    }

    #[test]
    fn test_convert_ebpf_end_to_sbpf_v2() {
        let mut data = RawSbpfData::new();
        data.text_bytes.extend_from_slice(&inst(0xd4, 1, 1, 0, 16)); // to_be 16
        data.text_bytes.extend_from_slice(&inst(0xd4, 2, 0, 0, 16)); // to_le 16
        data.text_bytes.extend_from_slice(&inst(0xd4, 3, 0, 0, 64)); // to_le 64

        data.convert_ebpf_to_sbpf_v2().unwrap();

        assert_eq!(data.text_bytes[0], 0xdc);
        assert_eq!(data.text_bytes[1] & 0xf0, 0); // src=0

        assert_eq!(data.text_bytes[8], 0x54);
        let imm16 = i32::from_le_bytes(data.text_bytes[12..16].try_into().unwrap());
        assert_eq!(imm16, 0x0000ffff);

        assert_eq!(data.text_bytes[16], 0xbf);
        let imm64 = i32::from_le_bytes(data.text_bytes[20..24].try_into().unwrap());
        assert_eq!(imm64, 0);
    }

    #[test]
    fn test_convert_ebpf_lddw_to_sbpf_v2() {
        let mut data = RawSbpfData::new();
        let mut lddw = [0u8; 16];
        lddw[0] = 0x18; // lddw
        lddw[1] = 1; // dst=r1
        lddw[4..8].copy_from_slice(&0x0101_0101u32.to_le_bytes());
        lddw[12..16].copy_from_slice(&0x0202_0202u32.to_le_bytes());
        data.text_bytes.extend_from_slice(&lddw);

        data.convert_ebpf_to_sbpf_v2().unwrap();

        assert_eq!(data.text_bytes[0], 0xb4); // mov32 imm
        assert_eq!(data.text_bytes[1] & 0x0f, 1);
        let imm_lo = i32::from_le_bytes(data.text_bytes[4..8].try_into().unwrap());
        assert_eq!(imm_lo as u32, 0x0101_0101);

        assert_eq!(data.text_bytes[8], 0xf7); // hor64 imm
        assert_eq!(data.text_bytes[9] & 0x0f, 1);
        let imm_hi = i32::from_le_bytes(data.text_bytes[12..16].try_into().unwrap());
        assert_eq!(imm_hi as u32, 0x0202_0202);
    }
}
