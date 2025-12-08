use anyhow::Result;
use std::collections::HashMap;

use object::elf;
use object::write::elf::{
    FileHeader, ProgramHeader, Rel, SectionHeader, SectionIndex, Sym, SymbolIndex, Writer,
};
use object::write::StringId;
use object::Endianness;

use crate::raw_parser::RawSbpfData;

const DYNAMIC_COUNT: usize = 10;
const R_BPF_64_RELATIVE: u32 = 8;

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

    fn reserve_layout(&mut self, sbpf: &RawSbpfData) -> Layout {
        let text_size = sbpf.text_bytes.len();
        let relocation_count = sbpf.relocations.len();

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
        let _shstrtab_index = self
            .writer
            .reserve_shstrtab_section_index_with_name(b".s");

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
        let mut dynstr_size = 1u64; // Starting empty string
        for reloc in &sbpf.relocations {
            if !reloc.is_syscall {
                // Record rodata absolute addresses for LDDW and RELATIVE relocations
                let key_name = if reloc.symbol_name.is_empty() {
                    format!("rodata_{:x}", reloc.symbol_address)
                } else {
                    reloc.symbol_name.clone()
                };
                if rodata_addrs.contains_key(&key_name) {
                    continue;
                }
                if let Some(off) = sbpf.rodata_symbols.get(&reloc.symbol_name) {
                    rodata_addrs.insert(key_name, rodata_offset as u64 + *off);
                } else if reloc.symbol_address != 0 {
                    rodata_addrs.insert(key_name, rodata_offset as u64 + reloc.symbol_address);
                }
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
            syscall_symbols.push(SymbolEntry { name_id, value: None });
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
        let rel_dyn_offset = self
            .writer
            .reserve_relocations(relocation_count, false);

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
        let rodata_filesz = rodata_end.saturating_sub(layout.dynsym_offset as u64);
        let text_ro_end = (layout.rodata_offset as u64 + rodata_size).max(layout.text_offset as u64 + text_size);
        let entry = layout.entry;

        // File header + program headers
        self.writer.write_file_header(&FileHeader {
            os_abi: elf::ELFOSABI_NONE,
            abi_version: 0,
            e_type: elf::ET_DYN,
            e_machine: elf::EM_BPF,
            e_entry: entry,
            e_flags: 0,
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
            p_offset: layout.dynsym_offset as u64,
            p_vaddr: layout.dynsym_offset as u64,
            p_paddr: layout.dynsym_offset as u64,
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
            let key_name = if reloc.symbol_name.is_empty() {
                format!("rodata_{:x}", reloc.symbol_address)
            } else {
                reloc.symbol_name.clone()
            };
            // For non-syscall, directly write rodata absolute addresses
            if reloc.is_syscall {
                continue;
            }
            if let Some(val) = layout.rodata_addrs.get(&key_name) {
                let imm_offset = reloc.offset as usize + 4;
                if imm_offset + 4 <= patched_text.len() {
                    patched_text[imm_offset..imm_offset + 4]
                        .copy_from_slice(&(*val as u32).to_le_bytes());
                }
            }
        }
        self.writer.write_align(4);
        self.writer.write(&patched_text);
        if layout.rodata_size > 0 {
            self.writer.write(&sbpf.rodata_bytes);
        }

        self.writer.write_align_dynamic();
        self.writer.write_dynamic(elf::DT_FLAGS, elf::DF_TEXTREL as u64);
        self.writer
            .write_dynamic(elf::DT_REL, layout.rel_dyn_offset as u64);
        self.writer.write_dynamic(elf::DT_RELSZ, rel_dyn_size);
        self.writer.write_dynamic(elf::DT_RELENT, 0x10);
        self.writer
            .write_dynamic(elf::DT_RELCOUNT, layout.relocation_count as u64);
        self.writer
            .write_dynamic(elf::DT_SYMTAB, layout.dynsym_offset as u64);
        self.writer.write_dynamic(elf::DT_SYMENT, 0x18);
        self.writer
            .write_dynamic(elf::DT_STRTAB, layout.dynstr_offset as u64);
        self.writer.write_dynamic(elf::DT_STRSZ, layout.dynstr_size);
        self.writer.write_dynamic(elf::DT_TEXTREL, 0);

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
            } else {
                // rodata etc. use R_BPF_64_RELATIVE, sym=0, plus rodata absolute address
                let key_name = if reloc.symbol_name.is_empty() {
                    format!("rodata_{:x}", reloc.symbol_address)
                } else {
                    reloc.symbol_name.clone()
                };
                if let Some(val) = layout.rodata_addrs.get(&key_name) {
                    self.writer.write_relocation(
                        false,
                        &Rel {
                            r_offset: layout.text_offset as u64 + reloc.offset,
                            r_sym: 0,
                            r_type: R_BPF_64_RELATIVE,
                            r_addend: *val as i64,
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
        if layout.rodata_size > 0 {
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
        }
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