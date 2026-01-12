use anyhow::Result;
use std::collections::HashMap;

use object::Endianness;
use object::elf;
use object::write::StringId;
use object::write::elf::{
    FileHeader, ProgramHeader, Rel, SectionHeader, SectionIndex, Sym, SymbolIndex, Writer,
};

use crate::raw_parser::{RawRelocation, RawSbpfData};

const DYNAMIC_COUNT: usize = 10;
const R_BPF_64_RELATIVE: u32 = 8;
const EF_SBPF_V2: u32 = 2;
const MM_RODATA_START: u64 = 1u64 << 32;

struct SymbolEntry {
    name_id: StringId,
    value: Option<u64>,
}
#[derive(thiserror::Error, Debug)]
pub enum ElfBuildError {
    #[error("Object write error: {0}")]
    ObjectWrite(#[from] object::write::Error),
}

struct Layout {
    text_size: usize,
    rodata_size: usize,
    relocation_count: usize,
    dynsym_count: u32,
    dynstr_size: u64,
    text_offset: usize,
    rodata_offset: usize,
    dynamic_offset: usize,
    dynsym_offset: usize,
    dynstr_offset: usize,
    rel_dyn_offset: usize,
    entry: u64,
    text_index: SectionIndex,
    rodata_index: SectionIndex,
    dynsym_index: SectionIndex,
    text_name: StringId,
    rodata_name: StringId,
    rel_dyn_name: StringId,
    syscall_symbols: Vec<SymbolEntry>,
    syscall_lookup: HashMap<String, SymbolIndex>,
    rodata_addrs: HashMap<String, u64>,
}

pub struct ElfObject<'a> {
    writer: Writer<'a>,
}

impl<'a> ElfObject<'a> {
    pub fn new(buffer: &'a mut Vec<u8>) -> ElfObject<'a> {
        ElfObject {
            writer: Writer::new(Endianness::Little, true, buffer),
        }
    }

    /// Generate ELF based on RawSbpfData
    pub fn gen_elf(&mut self, sbpf: &RawSbpfData) -> Result<()> {
        let layout = self.reserve_layout(sbpf);
        self.write_elf(sbpf, &layout)?;
        Ok(())
    }

    fn read_imm64(text_bytes: &[u8], offset: u64) -> Option<u64> {
        let low_offset = offset as usize + 4;
        let high_offset = offset as usize + 12;
        if high_offset + 4 > text_bytes.len() {
            return None;
        }
        let lo = u32::from_le_bytes(text_bytes[low_offset..low_offset + 4].try_into().ok()?);
        let hi = u32::from_le_bytes(text_bytes[high_offset..high_offset + 4].try_into().ok()?);
        Some((hi as u64) << 32 | lo as u64)
    }

    fn rodata_addr_for_reloc(layout: &Layout, sbpf: &RawSbpfData, reloc: &RawRelocation) -> Option<u64> {
        if reloc.is_syscall || reloc.is_text_section || !reloc.is_rodata_section {
            return None;
        }
        let key_name = if reloc.symbol_name.is_empty() {
            format!("rodata_{:x}", reloc.symbol_address)
        } else {
            reloc.symbol_name.clone()
        };
        let base = *layout.rodata_addrs.get(&key_name)?;
        let addend = if reloc.addend != 0 {
            if reloc.addend >= 0 {
                reloc.addend as u64
            } else {
                reloc.addend.wrapping_abs() as u64
            }
        } else {
            Self::read_imm64(&sbpf.text_bytes, reloc.offset)?
        };
        base.checked_add(addend)
    }

    fn reserve_layout(&mut self, sbpf: &RawSbpfData) -> Layout {
        let text_size = sbpf.text_bytes.len();
        let relocation_count = sbpf
            .relocations
            .iter()
            .filter(|reloc| {
                if reloc.is_text_section {
                    return false;
                }
                if reloc.is_syscall {
                    return true;
                }
                if sbpf.sbpf_v2 {
                    return false;
                }
                reloc.is_rodata_section
            })
            .count();

        // Reserve file header and program headers
        self.writer.reserve_file_header();
        self.writer.reserve_program_headers(3);

        // Section names
        let text_name = self.writer.add_section_name(b".text");
        let rodata_name = self.writer.add_section_name(b".rodata");
        let rel_dyn_name = self.writer.add_section_name(b".rel.dyn");

        // Section indices (must be done before reserve_section_headers)
        let text_index = self.writer.reserve_section_index();
        let rodata_index = self.writer.reserve_section_index();
        let _dynamic_index = self.writer.reserve_dynamic_section_index();
        let dynsym_index = self.writer.reserve_dynsym_section_index();
        let _dynstr_index = self.writer.reserve_dynstr_section_index();
        let _rel_dyn_index = self.writer.reserve_section_index();
        let _shstrtab_index = self.writer.reserve_shstrtab_section_index_with_name(b".s");

        // Section content space: text / rodata / dynamic placeholder first
        let text_offset = self.writer.reserve(text_size, 4);
        let rodata_offset = if !sbpf.rodata_bytes.is_empty() {
            self.writer.reserve(sbpf.rodata_bytes.len(), 1)
        } else {
            text_offset + text_size
        };
        let dynamic_offset = self.writer.reserve_dynamic(DYNAMIC_COUNT);

        // Dynamic symbols and strings: only for syscalls
        self.writer.reserve_null_dynamic_symbol_index();
        let mut syscall_lookup = HashMap::new();
        let mut syscall_symbols = Vec::new();
        let mut rodata_addrs = HashMap::new();
        let rodata_addr_base = if sbpf.sbpf_v2 {
            MM_RODATA_START
        } else {
            0
        };
        let mut dynstr_size = 1u64; // Starting empty string
        for reloc in &sbpf.relocations {
            if reloc.is_text_section {
                continue;
            }
            if !reloc.is_syscall {
                // Record rodata absolute addresses for LDDW and RELATIVE relocations.
                // Important: only treat relocations as rodata if they are explicitly
                // rodata symbols (or anonymous, address-based rodata references).
                // Otherwise, we may accidentally patch CALL immediates and trigger
                // `RelativeJumpOutOfBounds` in the SBPF loader.
                if !reloc.is_rodata_section {
                    continue;
                }
                let (key_name, abs_addr) = if !reloc.symbol_name.is_empty() {
                    if let Some(off) = sbpf.rodata_symbols.get(&reloc.symbol_name) {
                        (
                            reloc.symbol_name.clone(),
                            rodata_addr_base + rodata_offset as u64 + *off,
                        )
                    } else {
                        (
                            format!("rodata_{:x}", reloc.symbol_address),
                            rodata_addr_base + rodata_offset as u64 + reloc.symbol_address,
                        )
                    }
                } else {
                    (
                        format!("rodata_{:x}", reloc.symbol_address),
                        rodata_addr_base + rodata_offset as u64 + reloc.symbol_address,
                    )
                };
                if rodata_addrs.contains_key(&key_name) {
                    continue;
                }
                rodata_addrs.insert(key_name, abs_addr);
                continue;
            }
            if syscall_lookup.contains_key(&reloc.symbol_name) {
                continue;
            }
            let leaked: &'static [u8] =
                Box::leak(reloc.symbol_name.clone().into_bytes().into_boxed_slice());
            let sym = self.writer.reserve_dynamic_symbol_index();
            let name_id = self.writer.add_dynamic_string(leaked);

            dynstr_size += leaked.len() as u64 + 1;
            syscall_symbols.push(SymbolEntry {
                name_id,
                value: None,
            });
            syscall_lookup.insert(reloc.symbol_name.clone(), sym);
        }
        if dynstr_size < 0x10 {
            let leaked: &'static [u8] = Box::leak(b"pad__".to_vec().into_boxed_slice());
            let _pad = self.writer.add_dynamic_string(leaked);
            dynstr_size += leaked.len() as u64 + 1;
        }

        // Now reserve dynsym/dynstr/rel.dyn based on added symbols/strings
        let dynsym_offset = self.writer.reserve_dynsym();
        let dynstr_offset = self.writer.reserve_dynstr();
        let rel_dyn_offset = self.writer.reserve_relocations(relocation_count, false);

        // Finally reserve shstrtab and section table
        self.writer.reserve_shstrtab();
        self.writer.reserve_section_headers();

        Layout {
            text_size,
            relocation_count,
            dynsym_count: (syscall_symbols.len() as u32) + 1, // null + syscalls
            dynstr_size,
            text_offset,
            rodata_offset,
            dynamic_offset,
            dynsym_offset,
            dynstr_offset,
            rel_dyn_offset,
            rodata_size: sbpf.rodata_bytes.len(),
            entry: text_offset as u64 + sbpf.entry_address,
            text_index,
            rodata_index,
            dynsym_index,
            text_name,
            rodata_name,
            rel_dyn_name,
            syscall_symbols,
            syscall_lookup,
            rodata_addrs,
        }
    }

    fn write_elf(&mut self, sbpf: &RawSbpfData, layout: &Layout) -> Result<()> {
        let text_size = layout.text_size as u64;
        let rodata_size = layout.rodata_size as u64;
        let dynamic_size = (DYNAMIC_COUNT as u64) * 0x10;
        let rel_dyn_size = (layout.relocation_count as u64) * 0x10;
        let rodata_end = if layout.relocation_count > 0 {
            layout.rel_dyn_offset as u64 + rel_dyn_size
        } else {
            layout.dynstr_offset as u64 + layout.dynstr_size
        };
        let rodata_start = if rodata_size > 0 {
            layout.rodata_offset as u64
        } else {
            layout.dynsym_offset as u64
        };
        let rodata_filesz = rodata_end.saturating_sub(rodata_start);
        let text_ro_end = layout.text_offset as u64 + text_size;
        let entry = layout.entry;

        // File header + program headers
        self.writer.write_file_header(&FileHeader {
            os_abi: elf::ELFOSABI_NONE,
            abi_version: 0,
            e_type: elf::ET_DYN,
            e_machine: elf::EM_SBF,
            e_entry: entry,
            e_flags: if sbpf.sbpf_v2 { EF_SBPF_V2 } else { 0 },
        })?;
        self.writer.write_align_program_headers();

        self.writer.write_program_header(&ProgramHeader {
            p_type: elf::PT_LOAD,
            p_flags: elf::PF_R | elf::PF_X,
            p_offset: layout.text_offset as u64,
            p_vaddr: layout.text_offset as u64,
            p_paddr: layout.text_offset as u64,
            p_filesz: text_ro_end - layout.text_offset as u64,
            p_memsz: text_ro_end - layout.text_offset as u64,
            p_align: 0x1000,
        });
        self.writer.write_program_header(&ProgramHeader {
            p_type: elf::PT_LOAD,
            p_flags: elf::PF_R,
            p_offset: rodata_start,
            p_vaddr: rodata_start,
            p_paddr: rodata_start,
            p_filesz: rodata_filesz,
            p_memsz: rodata_filesz,
            p_align: 0x1000,
        });
        self.writer.write_program_header(&ProgramHeader {
            p_type: elf::PT_DYNAMIC,
            p_flags: elf::PF_R | elf::PF_W,
            p_offset: layout.dynamic_offset as u64,
            p_vaddr: layout.dynamic_offset as u64,
            p_paddr: layout.dynamic_offset as u64,
            p_filesz: dynamic_size,
            p_memsz: dynamic_size,
            p_align: 8,
        });

        // Section data
        let mut patched_text = sbpf.text_bytes.clone();
        for reloc in &sbpf.relocations {
            // For non-syscall, directly write rodata absolute addresses
            if reloc.is_syscall {
                continue;
            }
            if reloc.is_text_section {
                continue;
            }
            if let Some(val) = Self::rodata_addr_for_reloc(layout, sbpf, reloc) {
                let imm_offset = reloc.offset as usize + 4;
                if sbpf.sbpf_v2 {
                    let hi_offset = reloc.offset as usize + 12;
                    if imm_offset + 4 <= patched_text.len()
                        && hi_offset + 4 <= patched_text.len()
                    {
                        patched_text[imm_offset..imm_offset + 4]
                            .copy_from_slice(&(val as u32).to_le_bytes());
                        patched_text[hi_offset..hi_offset + 4]
                            .copy_from_slice(&((val >> 32) as u32).to_le_bytes());
                    }
                } else if imm_offset + 4 <= patched_text.len() {
                    patched_text[imm_offset..imm_offset + 4]
                        .copy_from_slice(&(val as u32).to_le_bytes());
                }
            }
        }
        self.writer.write_align(4);
        self.writer.write(&patched_text);
        if layout.rodata_size > 0 {
            self.writer.write(&sbpf.rodata_bytes);
        }

        self.writer.write_align_dynamic();
        let rel_addr = if rel_dyn_size > 0 {
            layout.rel_dyn_offset as u64
        } else {
            0
        };

        // If there are no relocations, avoid emitting a DT_REL pointer that points outside any
        // PT_LOAD segment, otherwise mollusk will fail with "invalid dynamic section table".
        self.writer.write_dynamic(
            elf::DT_FLAGS,
            if rel_dyn_size > 0 {
                elf::DF_TEXTREL as u64
            } else {
                0
            },
        );
        self.writer.write_dynamic(elf::DT_REL, rel_addr);
        self.writer.write_dynamic(elf::DT_RELSZ, rel_dyn_size);
        self.writer.write_dynamic(elf::DT_RELENT, 0x10);
        self.writer.write_dynamic(
            elf::DT_RELCOUNT,
            if rel_dyn_size > 0 {
                layout.relocation_count as u64
            } else {
                0
            },
        );
        self.writer
            .write_dynamic(elf::DT_SYMTAB, layout.dynsym_offset as u64);
        self.writer.write_dynamic(elf::DT_SYMENT, 0x18);
        self.writer
            .write_dynamic(elf::DT_STRTAB, layout.dynstr_offset as u64);
        self.writer.write_dynamic(elf::DT_STRSZ, layout.dynstr_size);
        self.writer
            .write_dynamic(elf::DT_TEXTREL, if rel_dyn_size > 0 { 0 } else { 0 });

        self.writer.write_null_dynamic_symbol();
        for symbol in &layout.syscall_symbols {
            // Write dynamic symbol table in reserved order
            self.writer.write_dynamic_symbol(&Sym {
                name: Some(symbol.name_id),
                section: None,
                st_info: ((elf::STB_GLOBAL << 4) | elf::STT_NOTYPE) as u8,
                st_other: elf::STV_DEFAULT,
                st_shndx: elf::SHN_UNDEF as u16,
                st_value: 0,
                st_size: 0,
            });
        }

        self.writer.write_dynstr();

        self.writer.write_align_relocation();
        for reloc in &sbpf.relocations {
            if reloc.is_text_section {
                continue;
            }
            if reloc.is_syscall {
                // syscall uses R_BPF_64_32 + dynsym
                if let Some(sym) = layout.syscall_lookup.get(&reloc.symbol_name) {
                    self.writer.write_relocation(
                        false,
                        &Rel {
                            r_offset: layout.text_offset as u64 + reloc.offset,
                            r_sym: sym.0,
                            r_type: elf::R_BPF_64_32,
                            r_addend: reloc.addend,
                        },
                    );
                }
            } else if !sbpf.sbpf_v2 {
                // rodata etc. use R_BPF_64_RELATIVE, sym=0, plus rodata absolute address
                if let Some(val) = Self::rodata_addr_for_reloc(layout, sbpf, reloc) {
                    self.writer.write_relocation(
                        false,
                        &Rel {
                            r_offset: layout.text_offset as u64 + reloc.offset,
                            r_sym: 0,
                            r_type: R_BPF_64_RELATIVE,
                            r_addend: val as i64,
                        },
                    );
                }
            }
        }

        self.writer.write_shstrtab();

        // Section headers (order consistent with reserved indices)
        self.writer.write_null_section_header();
        self.writer.write_section_header(&SectionHeader {
            name: Some(layout.text_name),
            sh_type: elf::SHT_PROGBITS,
            sh_flags: (elf::SHF_ALLOC | elf::SHF_EXECINSTR) as u64,
            sh_addr: layout.text_offset as u64,
            sh_offset: layout.text_offset as u64,
            sh_size: text_size,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 4,
            sh_entsize: 0,
        });
        self.writer.write_section_header(&SectionHeader {
            name: Some(layout.rodata_name),
            sh_type: elf::SHT_PROGBITS,
            sh_flags: elf::SHF_ALLOC as u64,
            sh_addr: layout.rodata_offset as u64,
            sh_offset: layout.rodata_offset as u64,
            sh_size: rodata_size,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 1,
            sh_entsize: 0,
        });
        self.writer
            .write_dynamic_section_header(layout.dynamic_offset as u64);
        self.writer.write_dynsym_section_header(
            layout.dynsym_offset as u64,
            layout.dynsym_count.saturating_sub(1),
        );
        self.writer
            .write_dynstr_section_header(layout.dynstr_offset as u64);
        // .rel.dyn needs SHF_ALLOC, otherwise loader won't apply relocations
        self.writer.write_section_header(&SectionHeader {
            name: Some(layout.rel_dyn_name),
            sh_type: elf::SHT_REL,
            sh_flags: (elf::SHF_ALLOC) as u64,
            sh_addr: layout.rel_dyn_offset as u64,
            sh_offset: layout.rel_dyn_offset as u64,
            sh_size: (layout.relocation_count as u64) * 0x10,
            sh_link: layout.dynsym_index.0,
            sh_info: 0,
            sh_addralign: 8,
            sh_entsize: 0x10,
        });
        self.writer.write_shstrtab_section_header();

        Ok(())
    }
}
pub fn build_sbpf_so(data: &RawSbpfData) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    {
        let mut elf_obj = ElfObject::new(&mut buffer);
        elf_obj.gen_elf(data)?;
    }
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw_parser::RawRelocation;

    #[test]
    fn build_sbpf_so_has_complete_section_table_when_rodata_empty() {
        let mut data = RawSbpfData::new();
        data.text_bytes = vec![0u8; 16];
        data.rodata_bytes = Vec::new();

        let elf = build_sbpf_so(&data).expect("ELF build should succeed");
        assert!(!elf.is_empty());

        let e_shoff = u64::from_le_bytes(elf[0x28..0x30].try_into().unwrap()) as usize;
        let e_shentsize = u16::from_le_bytes(elf[0x3A..0x3C].try_into().unwrap()) as usize;
        let e_shnum = u16::from_le_bytes(elf[0x3C..0x3E].try_into().unwrap()) as usize;
        let section_table_end = e_shoff + (e_shentsize * e_shnum);
        assert!(
            section_table_end <= elf.len(),
            "section table overruns file: end={section_table_end} len={}",
            elf.len()
        );
    }

    #[test]
    fn build_sbpf_so_skips_non_rodata_non_syscall_relocs() {
        let mut data = RawSbpfData::new();
        data.text_bytes = vec![0u8; 16];
        data.relocations.push(RawRelocation {
            offset: 0,
            symbol_name: "_ZN4core9panicking18panic_bounds_check17hf0c02a9253951be5E".into(),
            symbol_address: 0,
            is_syscall: false,
            is_core_lib: true,
            addend: 0,
            is_text_section: false,
            is_rodata_section: false,
            target_section_base: None,
        });

        let elf = build_sbpf_so(&data).expect("ELF build should succeed");
        assert!(!elf.is_empty());
    }
}
