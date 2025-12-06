use object::ObjectSection;
use object::{Object as _, ObjectSymbol as _}; // 导入 Object 和 ObjectSymbol trait
use std::collections::HashMap;

/// Solana SBPF 注册的系统调用列表
/// 这些 syscall 在重定位时需要转换为 murmur3_32 哈希值
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

/// 原始SBPF数据结构
/// 基于原始byteparser.rs的完整数据提取
#[derive(Debug)]
pub struct RawSbpfData {
    pub text_bytes: Vec<u8>,             // .text段原始字节
    pub rodata_bytes: Vec<u8>,         // .rodata段原始字节
    pub symbols: HashMap<String, u64>, // 符号名 -> 地址
    pub relocations: Vec<RawRelocation>, // 完整的重定位信息
    pub entry_address: u64,
}

/// 重定位信息 (基于原始byteparser.rs的处理逻辑)
#[derive(Debug, Clone)]
pub struct RawRelocation {
    pub offset: u64,        // 在.text中的偏移
    pub symbol_name: String,
    pub symbol_address: u64,
    pub is_syscall: bool,   // 是否为REGISTERED_SYSCALLS中的syscall
    pub is_core_lib: bool,  // 是否为Rust核心库符号 (_ZN4core开头)
    pub addend: i64,        // 附加值
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
        Self {
            text_bytes: Vec::new(),
            rodata_bytes: Vec::new(),
            symbols: HashMap::new(),
            relocations: Vec::new(),
            entry_address: 0,
        }
    }

    /// 从 object 文件中提取原始 SBPF 数据
    pub fn from_object_file(bytes: &[u8]) -> Result<Self, RawSbpfError> {
        let obj = object::File::parse(bytes)?;
        let mut result = Self::new();

        // 提取符号表
        result.extract_symbols(&obj)?;

        // 提取 .text 段
        result.extract_text_section(&obj)?;

        // 提取 .rodata 段
        result.extract_rodata_section(&obj)?;

        // 提取重定位信息
        result.extract_relocations(&obj)?;

        Ok(result)
    }

    /// 提取符号表
    fn extract_symbols(&mut self, obj: &object::File) -> Result<(), RawSbpfError> {
        for symbol in obj.symbols() {
            if symbol.kind() == object::SymbolKind::Text {
                if let Ok(name) = symbol.name() {
                    self.symbols.insert(name.to_string(), symbol.address());
                    if name == "entrypoint" {
                        self.entry_address = symbol.address();
                    }
                }
            }
        }
        Ok(())
    }

    /// 提取 .text 段原始字节
    fn extract_text_section(&mut self, obj: &object::File) -> Result<(), RawSbpfError> {
        for section in obj.sections() {
            if section.name() == Ok(".text") {
                let data = section.data()?;
                self.text_bytes = data.to_vec();
                println!("提取.text段: {} 字节", data.len());

                // 验证指令完整性
                self.validate_text_instructions()?;
                break;
            }
        }
        Ok(())
    }

    /// 验证.text段中的指令完整性
    fn validate_text_instructions(&self) -> Result<(), RawSbpfError> {
        let mut offset = 0;
        let mut instruction_count = 0;

        while offset < self.text_bytes.len() {
            if offset + 8 > self.text_bytes.len() {
                println!("警告: .text段在偏移0x{:x}处不完整，剩余{}字节", offset, self.text_bytes.len() - offset);
                break;
            }

            // 检查是否为双字指令 (LDDW)
            // LDDW指令的格式: opcode=0x18, imm=0, src=0
            let opcode = self.text_bytes[offset];
            let inst_len = if opcode == 0x18 { 16 } else { 8 };

            if offset + inst_len > self.text_bytes.len() {
                println!("警告: 指令在偏移0x{:x}处不完整，需要{}字节，剩余{}字节",
                        offset, inst_len, self.text_bytes.len() - offset);
                break;
            }

            offset += inst_len;
            instruction_count += 1;
        }

        println!("验证结果: {} 条指令，总大小 {} 字节", instruction_count, self.text_bytes.len());
        Ok(())
    }

    /// 提取 .rodata 段
    fn extract_rodata_section(&mut self, obj: &object::File) -> Result<(), RawSbpfError> {
        for section in obj.sections() {
            if section.name()?.starts_with(".rodata") {
                self.rodata_bytes.extend_from_slice(section.data()?);
            }
        }
        Ok(())
    }

    /// 提取重定位信息
    fn extract_relocations(&mut self, obj: &object::File) -> Result<(), RawSbpfError> {
        for section in obj.sections() {
            if section.name() == Ok(".text") {
                for (offset, rel) in section.relocations() {
                    if let object::RelocationTarget::Symbol(sym_idx) = rel.target() {
                        if let Some(symbol) = obj.symbol_by_index(sym_idx).ok() {
                            if let Ok(symbol_name) = symbol.name() {
                                let symbol_name_str = symbol_name.to_string();
                                let is_syscall = REGISTERED_SYSCALLS.contains(&symbol_name_str.as_str());
                                let is_core_lib = symbol_name_str.starts_with("_ZN4core");

                                self.relocations.push(RawRelocation {
                                    offset,
                                    symbol_name: symbol_name_str,
                                    symbol_address: symbol.address(),
                                    is_syscall,
                                    is_core_lib,
                                    addend: rel.addend(),
                                });
                            }
                        }
                    }
                }
                break;
            }
        }
        Ok(())
    }

    /// 应用重定位
    pub fn apply_relocations(&mut self) -> Result<(), RawSbpfError> {
        println!("应用重定位前: .text段大小 = {}", self.text_bytes.len());

        // 先收集所有需要应用的重定位，避免借用冲突
        let relocations: Vec<RawRelocation> = self.relocations.iter().cloned().collect();
        println!("需要应用 {} 个重定位", relocations.len());

        for reloc in relocations {
            println!("应用重定位: offset=0x{:x}, symbol={}, is_syscall={}, is_core_lib={}",
                    reloc.offset, reloc.symbol_name, reloc.is_syscall, reloc.is_core_lib);
            self.apply_relocation(&reloc)?;
        }

        println!("应用重定位后: .text段大小 = {}", self.text_bytes.len());
        Ok(())
    }

    /// 应用单个重定位 (基于原始byteparser.rs的逻辑)
    fn apply_relocation(&mut self, reloc: &RawRelocation) -> Result<(), RawSbpfError> {
        let value = if reloc.is_syscall {
            // Syscall: murmur3_32哈希 (与原始代码相同)
            crate::murmur3::murmur3_32(reloc.symbol_name.as_bytes()) as i64
        } else if reloc.is_core_lib {
            // Rust核心库: 保持附加值 (与原始代码相同)
            reloc.addend
        } else {
            // 其他外部符号: 使用符号地址 + 附加值 (与原始代码相同)
            (reloc.symbol_address as i64) + reloc.addend
        };

        self.patch_immediate(reloc.offset, value)?;
        Ok(())
    }

    /// 修补 immediate 字段
    fn patch_immediate(&mut self, offset: u64, value: i64) -> Result<(), RawSbpfError> {
        // BPF指令格式: opcode(1) + regs(1) + offset(2) + immediate(4)
        // immediate 字段使用小端序存储，32位

        let imm_offset = offset as usize + 4;

        // 检查边界
        if imm_offset + 4 > self.text_bytes.len() {
            return Err(RawSbpfError::UnsupportedRelocation {
                offset,
                symbol: "out_of_bounds".to_string(),
            });
        }

        // 将i64转换为i32（BPF immediate是32位），然后转换为字节
        let imm_value = value as i32;
        let bytes = imm_value.to_le_bytes();
        self.text_bytes[imm_offset..imm_offset + 4].copy_from_slice(&bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_sbpf_data_new() {
        let data = RawSbpfData::new();
        assert!(data.text_bytes.is_empty());
        assert!(data.rodata_bytes.is_empty());
        assert!(data.symbols.is_empty());
        assert!(data.relocations.is_empty());
        assert_eq!(data.entry_address, 0);
    }
}
