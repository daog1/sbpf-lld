use anyhow::{bail, Result};
use std::collections::HashMap;

use object::Endianness;
use object::elf;
use object::write::StringId;
use object::write::elf::{
    FileHeader, ProgramHeader, Rel, SectionHeader, SectionIndex, Sym, SymbolIndex, Writer,
};

use crate::raw_parser::{RawRelocation, RawSbpfData};
use crate::SbpfVersion;

const DYNAMIC_COUNT: usize = 10;
const EF_SBPF_V2: u32 = 2;
const EF_SBPF_V3: u32 = 3;
const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
const INSN_ALIGN: usize = 8;
const MM_BYTECODE_START: u64 = 0;
const MM_RODATA_START: u64 = 1u64 << 32;
const MM_STACK_START: u64 = 2u64 << 32;
const MM_HEAP_START: u64 = 3u64 << 32;

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
    rodata_file_size: usize,
    relocation_count: usize,
    dynsym_count: u32,
    dynstr_size: u64,
    text_offset: usize,
    rodata_offset: usize,
    dynamic_offset: Option<usize>,
    dynsym_offset: Option<usize>,
    dynstr_offset: Option<usize>,
    rel_dyn_offset: Option<usize>,
    entry: u64,
    text_index: SectionIndex,
    rodata_index: SectionIndex,
    dynsym_index: Option<SectionIndex>,
    text_name: StringId,
    rodata_name: StringId,
    rel_dyn_name: Option<StringId>,
    syscall_symbols: Vec<SymbolEntry>,
    syscall_lookup: HashMap<String, SymbolIndex>,
    rodata_addrs: HashMap<String, u64>,
    text_vaddr: u64,
    rodata_vaddr: u64,
    uses_dynamic: bool,
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
        fn align_up(value: usize, align: usize) -> usize {
            if align == 0 {
                value
            } else {
                (value + align - 1) & !(align - 1)
            }
        }

        let text_size = sbpf.text_bytes.len();
        let rodata_size = sbpf.rodata_bytes.len();
        let rodata_file_size = if sbpf.sbpf_version.is_v3() {
            align_up(rodata_size, INSN_ALIGN)
        } else {
            rodata_size
        };
        let uses_dynamic = matches!(sbpf.sbpf_version, SbpfVersion::V2);
        let program_header_count: u32 = if sbpf.sbpf_version.is_v3() { 4 } else { 3 };
        let relocation_count = if uses_dynamic {
            sbpf.relocations
                .iter()
                .filter(|reloc| {
                    if reloc.is_text_section {
                        return false;
                    }
                    reloc.is_syscall
                })
                .count()
        } else {
            0
        };

        // Reserve file header and program headers
        self.writer.reserve_file_header();
        self.writer
            .reserve_program_headers(program_header_count);

        // Section names
        let text_name = self.writer.add_section_name(b".text");
        let rodata_name = self.writer.add_section_name(b".rodata");
        let rel_dyn_name = if uses_dynamic {
            Some(self.writer.add_section_name(b".rel.dyn"))
        } else {
            None
        };

        // Section indices (must be done before reserve_section_headers)
        let text_index = self.writer.reserve_section_index();
        let rodata_index = self.writer.reserve_section_index();
        let dynsym_index = if uses_dynamic {
            let _dynamic_index = self.writer.reserve_dynamic_section_index();
            let dynsym_index = self.writer.reserve_dynsym_section_index();
            let _dynstr_index = self.writer.reserve_dynstr_section_index();
            let _rel_dyn_index = self.writer.reserve_section_index();
            Some(dynsym_index)
        } else {
            None
        };
        let _shstrtab_index = self
            .writer
            .reserve_shstrtab_section_index_with_name(b".s");

        // Section content space: text / rodata / dynamic placeholder first
        let text_align = if sbpf.sbpf_version.is_v3() {
            INSN_ALIGN
        } else {
            4
        };
        let rodata_align = if sbpf.sbpf_version.is_v3() {
            INSN_ALIGN
        } else {
            1
        };
        let phdr_table_end =
            ELF_HEADER_SIZE + program_header_count as usize * PROGRAM_HEADER_SIZE;
        let text_padding =
            align_up(phdr_table_end, text_align).saturating_sub(phdr_table_end);
        if text_padding > 0 {
            self.writer.reserve(text_padding, 1);
        }
        let text_offset = self.writer.reserve(text_size, text_align);
        let rodata_offset = if rodata_file_size > 0 {
            self.writer.reserve(rodata_file_size, rodata_align)
        } else {
            text_offset + text_size
        };
        let dynamic_offset = if uses_dynamic {
            Some(self.writer.reserve_dynamic(DYNAMIC_COUNT))
        } else {
            None
        };

        let text_vaddr = if sbpf.sbpf_version.is_v3() {
            MM_BYTECODE_START
        } else {
            text_offset as u64
        };
        let rodata_vaddr = if sbpf.sbpf_version.is_v3() {
            MM_RODATA_START
        } else {
            rodata_offset as u64
        };
        let rodata_addr_base = match sbpf.sbpf_version {
            SbpfVersion::V2 => MM_RODATA_START + rodata_offset as u64,
            SbpfVersion::V3 => MM_RODATA_START,
        };

        // Dynamic symbols and strings: only for v2 syscalls
        let mut syscall_lookup = HashMap::new();
        let mut syscall_symbols = Vec::new();
        let mut rodata_addrs = HashMap::new();
        let mut dynstr_size = 1u64; // Starting empty string
        if uses_dynamic {
            self.writer.reserve_null_dynamic_symbol_index();
        }
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
                        (reloc.symbol_name.clone(), rodata_addr_base + *off)
                    } else {
                        (
                            format!("rodata_{:x}", reloc.symbol_address),
                            rodata_addr_base + reloc.symbol_address,
                        )
                    }
                } else {
                    (
                        format!("rodata_{:x}", reloc.symbol_address),
                        rodata_addr_base + reloc.symbol_address,
                    )
                };
                if rodata_addrs.contains_key(&key_name) {
                    continue;
                }
                rodata_addrs.insert(key_name, abs_addr);
                continue;
            }
            if !uses_dynamic {
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
        if uses_dynamic && dynstr_size < 0x10 {
            let leaked: &'static [u8] = Box::leak(b"pad__".to_vec().into_boxed_slice());
            let _pad = self.writer.add_dynamic_string(leaked);
            dynstr_size += leaked.len() as u64 + 1;
        }

        // Now reserve dynsym/dynstr/rel.dyn based on added symbols/strings
        let (dynsym_offset, dynstr_offset, rel_dyn_offset, dynsym_count, dynstr_size) =
            if uses_dynamic {
                let dynsym_offset = self.writer.reserve_dynsym();
                let dynstr_offset = self.writer.reserve_dynstr();
                let rel_dyn_offset = self.writer.reserve_relocations(relocation_count, false);
                (
                    Some(dynsym_offset),
                    Some(dynstr_offset),
                    Some(rel_dyn_offset),
                    (syscall_symbols.len() as u32) + 1,
                    dynstr_size,
                )
            } else {
                (None, None, None, 0, 0)
            };

        // Finally reserve shstrtab and section table
        self.writer.reserve_shstrtab();
        self.writer.reserve_section_headers();

        Layout {
            text_size,
            rodata_size,
            rodata_file_size,
            relocation_count,
            dynsym_count,
            dynstr_size,
            text_offset,
            rodata_offset,
            dynamic_offset,
            dynsym_offset,
            dynstr_offset,
            rel_dyn_offset,
            entry: text_vaddr + sbpf.entry_address,
            text_index,
            rodata_index,
            dynsym_index,
            text_name,
            rodata_name,
            rel_dyn_name,
            syscall_symbols,
            syscall_lookup,
            rodata_addrs,
            text_vaddr,
            rodata_vaddr,
            uses_dynamic,
        }
    }

    fn write_elf(&mut self, sbpf: &RawSbpfData, layout: &Layout) -> Result<()> {
        let text_size = layout.text_size as u64;
        let rodata_size = layout.rodata_size as u64;
        let rodata_file_size = layout.rodata_file_size as u64;
        let dynamic_size = if layout.uses_dynamic {
            (DYNAMIC_COUNT as u64) * 0x10
        } else {
            0
        };
        let rel_dyn_size = if layout.uses_dynamic {
            (layout.relocation_count as u64) * 0x10
        } else {
            0
        };
        let rodata_start = if layout.uses_dynamic && rodata_size == 0 {
            layout
                .dynsym_offset
                .expect("dynsym_offset missing for dynamic layout") as u64
        } else {
            layout.rodata_offset as u64
        };
        let rodata_end = if layout.uses_dynamic {
            if layout.relocation_count > 0 {
                layout
                    .rel_dyn_offset
                    .expect("rel_dyn_offset missing for dynamic layout") as u64
                    + rel_dyn_size
            } else {
                layout
                    .dynstr_offset
                    .expect("dynstr_offset missing for dynamic layout") as u64
                    + layout.dynstr_size
            }
        } else {
            rodata_start + rodata_file_size
        };
        let rodata_filesz = if layout.uses_dynamic {
            rodata_end.saturating_sub(rodata_start)
        } else {
            rodata_file_size
        };
        let entry = layout.entry;
        let rodata_vaddr = layout.rodata_vaddr;

        // File header + program headers
        self.writer.write_file_header(&FileHeader {
            os_abi: elf::ELFOSABI_NONE,
            abi_version: 0,
            e_type: elf::ET_DYN,
            e_machine: elf::EM_SBF,
            e_entry: entry,
            e_flags: match sbpf.sbpf_version {
                SbpfVersion::V2 => EF_SBPF_V2,
                SbpfVersion::V3 => EF_SBPF_V3,
            },
        })?;
        self.writer.write_align_program_headers();

        if sbpf.sbpf_version.is_v3() {
            self.writer.write_program_header(&ProgramHeader {
                p_type: elf::PT_LOAD,
                p_flags: elf::PF_X,
                p_offset: layout.text_offset as u64,
                p_vaddr: MM_BYTECODE_START,
                p_paddr: MM_BYTECODE_START,
                p_filesz: text_size,
                p_memsz: text_size,
                p_align: 0x1000,
            });
            self.writer.write_program_header(&ProgramHeader {
                p_type: elf::PT_LOAD,
                p_flags: elf::PF_R,
                p_offset: rodata_start,
                p_vaddr: MM_RODATA_START,
                p_paddr: MM_RODATA_START,
                p_filesz: rodata_filesz,
                p_memsz: rodata_filesz,
                p_align: 0x1000,
            });
            self.writer.write_program_header(&ProgramHeader {
                p_type: elf::PT_LOAD,
                p_flags: elf::PF_R | elf::PF_W,
                p_offset: rodata_start,
                p_vaddr: MM_STACK_START,
                p_paddr: MM_STACK_START,
                p_filesz: 0,
                p_memsz: 0,
                p_align: 0x1000,
            });
            self.writer.write_program_header(&ProgramHeader {
                p_type: elf::PT_LOAD,
                p_flags: elf::PF_R | elf::PF_W,
                p_offset: rodata_start,
                p_vaddr: MM_HEAP_START,
                p_paddr: MM_HEAP_START,
                p_filesz: 0,
                p_memsz: 0,
                p_align: 0x1000,
            });
        } else {
            self.writer.write_program_header(&ProgramHeader {
                p_type: elf::PT_LOAD,
                p_flags: elf::PF_R | elf::PF_X,
                p_offset: layout.text_offset as u64,
                p_vaddr: layout.text_vaddr,
                p_paddr: layout.text_vaddr,
                p_filesz: text_size,
                p_memsz: text_size,
                p_align: 0x1000,
            });
            self.writer.write_program_header(&ProgramHeader {
                p_type: elf::PT_LOAD,
                p_flags: elf::PF_R,
                p_offset: rodata_start,
                p_vaddr: rodata_vaddr,
                p_paddr: rodata_vaddr,
                p_filesz: rodata_filesz,
                p_memsz: rodata_filesz,
                p_align: 0x1000,
            });
            if layout.uses_dynamic {
                let dynamic_offset = layout
                    .dynamic_offset
                    .expect("dynamic_offset missing for dynamic layout") as u64;
                self.writer.write_program_header(&ProgramHeader {
                    p_type: elf::PT_DYNAMIC,
                    p_flags: elf::PF_R | elf::PF_W,
                    p_offset: dynamic_offset,
                    p_vaddr: dynamic_offset,
                    p_paddr: dynamic_offset,
                    p_filesz: dynamic_size,
                    p_memsz: dynamic_size,
                    p_align: 8,
                });
            }
        }

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
                if matches!(sbpf.sbpf_version, SbpfVersion::V2 | SbpfVersion::V3) {
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
        self.writer
            .write_align(if sbpf.sbpf_version.is_v3() { INSN_ALIGN } else { 4 });
        self.writer.write(&patched_text);
        if layout.rodata_size > 0 {
            self.writer.write(&sbpf.rodata_bytes);
            let pad = layout.rodata_file_size.saturating_sub(layout.rodata_size);
            if pad > 0 {
                self.writer.write(&vec![0u8; pad]);
            }
        }

        if layout.uses_dynamic {
            self.writer.write_align_dynamic();
            let rel_addr = if rel_dyn_size > 0 {
                layout
                    .rel_dyn_offset
                    .expect("rel_dyn_offset missing for dynamic layout") as u64
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
            self.writer.write_dynamic(
                elf::DT_SYMTAB,
                layout
                    .dynsym_offset
                    .expect("dynsym_offset missing for dynamic layout") as u64,
            );
            self.writer.write_dynamic(elf::DT_SYMENT, 0x18);
            self.writer.write_dynamic(
                elf::DT_STRTAB,
                layout
                    .dynstr_offset
                    .expect("dynstr_offset missing for dynamic layout") as u64,
            );
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
            sh_addr: layout.text_vaddr,
            sh_offset: layout.text_offset as u64,
            sh_size: text_size,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: if sbpf.sbpf_version.is_v3() {
                INSN_ALIGN as u64
            } else {
                4
            },
            sh_entsize: 0,
        });
        self.writer.write_section_header(&SectionHeader {
            name: Some(layout.rodata_name),
            sh_type: elf::SHT_PROGBITS,
            sh_flags: elf::SHF_ALLOC as u64,
            sh_addr: rodata_vaddr,
            sh_offset: layout.rodata_offset as u64,
            sh_size: rodata_size,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: if sbpf.sbpf_version.is_v3() {
                INSN_ALIGN as u64
            } else {
                1
            },
            sh_entsize: 0,
        });
        if layout.uses_dynamic {
            self.writer.write_dynamic_section_header(
                layout
                    .dynamic_offset
                    .expect("dynamic_offset missing for dynamic layout") as u64,
            );
            self.writer.write_dynsym_section_header(
                layout
                    .dynsym_offset
                    .expect("dynsym_offset missing for dynamic layout") as u64,
                layout.dynsym_count.saturating_sub(1),
            );
            self.writer.write_dynstr_section_header(
                layout
                    .dynstr_offset
                    .expect("dynstr_offset missing for dynamic layout") as u64,
            );
            // .rel.dyn needs SHF_ALLOC, otherwise loader won't apply relocations
            self.writer.write_section_header(&SectionHeader {
                name: layout.rel_dyn_name,
                sh_type: elf::SHT_REL,
                sh_flags: (elf::SHF_ALLOC) as u64,
                sh_addr: layout
                    .rel_dyn_offset
                    .expect("rel_dyn_offset missing for dynamic layout") as u64,
                sh_offset: layout
                    .rel_dyn_offset
                    .expect("rel_dyn_offset missing for dynamic layout") as u64,
                sh_size: (layout.relocation_count as u64) * 0x10,
                sh_link: layout
                    .dynsym_index
                    .expect("dynsym_index missing for dynamic layout")
                    .0,
                sh_info: 0,
                sh_addralign: 8,
                sh_entsize: 0x10,
            });
        }
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
    if data.sbpf_version.is_v3() {
        fixup_v3_program_headers(&mut buffer)?;
    }
    Ok(buffer)
}

fn fixup_v3_program_headers(buffer: &mut [u8]) -> Result<()> {
    const PH_FLAGS_OFFSET: usize = 4;
    if buffer.len() < ELF_HEADER_SIZE {
        bail!("ELF buffer too small for header");
    }
    let e_phoff = u64::from_le_bytes(buffer[0x20..0x28].try_into().unwrap()) as usize;
    let e_phentsize = u16::from_le_bytes(buffer[0x36..0x38].try_into().unwrap()) as usize;
    let e_phnum = u16::from_le_bytes(buffer[0x38..0x3A].try_into().unwrap()) as usize;
    if e_phentsize == 0 || e_phnum < 4 {
        bail!("ELF program header table is invalid");
    }
    let ph_table_end = e_phoff
        .saturating_add(e_phentsize.saturating_mul(e_phnum as usize));
    if ph_table_end > buffer.len() {
        bail!("ELF program header table overruns buffer");
    }
    let expected_flags = [
        elf::PF_X,
        elf::PF_R,
        elf::PF_R | elf::PF_W,
        elf::PF_R | elf::PF_W,
    ];
    for (idx, flags) in expected_flags.iter().enumerate() {
        let off = e_phoff + idx * e_phentsize + PH_FLAGS_OFFSET;
        buffer[off..off + 4].copy_from_slice(&flags.to_le_bytes());
    }
    Ok(())
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

    #[test]
    fn build_sbpf_so_v3_sets_flags_and_vaddrs() {
        let mut data = RawSbpfData::new_with_version(SbpfVersion::V3);
        data.text_bytes = vec![0u8; 16];

        let elf = build_sbpf_so(&data).expect("ELF build should succeed");
        assert!(!elf.is_empty());

        let e_flags = u32::from_le_bytes(elf[0x30..0x34].try_into().unwrap());
        assert_eq!(e_flags, EF_SBPF_V3);

        let e_phoff = u64::from_le_bytes(elf[0x20..0x28].try_into().unwrap()) as usize;
        let e_phentsize = u16::from_le_bytes(elf[0x36..0x38].try_into().unwrap()) as usize;
        let e_phnum = u16::from_le_bytes(elf[0x38..0x3A].try_into().unwrap()) as usize;
        assert_eq!(e_phnum, 4);

        let text_flags =
            u32::from_le_bytes(elf[e_phoff + 4..e_phoff + 8].try_into().unwrap());
        assert_eq!(text_flags, super::elf::PF_X);

        let text_vaddr =
            u64::from_le_bytes(elf[e_phoff + 16..e_phoff + 24].try_into().unwrap());
        assert_eq!(text_vaddr, MM_BYTECODE_START);

        let rodata_off = e_phoff + e_phentsize;
        let rodata_vaddr =
            u64::from_le_bytes(elf[rodata_off + 16..rodata_off + 24].try_into().unwrap());
        assert_eq!(rodata_vaddr, MM_RODATA_START);
    }
}
