use object::Endianness;
use object::elf;
use object::write::StringId;
use object::write::elf::SectionIndex;
use object::write::elf::{FileHeader, ProgramHeader, Rel, SectionHeader, Sym, Writer};

use crate::raw_parser::{REGISTERED_SYSCALLS, RawSbpfData};

#[derive(thiserror::Error, Debug)]
pub enum ElfBuildError {
    #[error("Object write error: {0}")]
    ObjectWrite(#[from] object::write::Error),
}

/// 8字节对齐函数
fn align_to_eight(len: u64) -> u64 {
    (len + 7) & !7
}

/// ELF 构建布局信息
struct ElfLayout {
    text_offset: u64,
    text_size: u64,
    dynstr_offset: u64,
    dynstr_size: u64,
    dynsym_offset: u64,
    dynsym_size: u64,
    rel_dyn_offset: u64,
    rel_dyn_size: u64,
    dynamic_offset: u64,
    dynamic_size: u64,
}

/// 从 RawSbpfData 计算 ELF 布局
fn calculate_layout(data: &RawSbpfData) -> ElfLayout {
    // 基础常量
    let elf_header_size = 64u64;
    let program_header_size = 56u64;
    let program_header_count = 3u64;

    // 1. 计算基础偏移量 (ELF头 + 程序头)
    let mut current_offset = elf_header_size + (program_header_count * program_header_size);

    // 2. .text段 - 16字节对齐
    let text_offset = align_to_eight(current_offset); // 确保16字节对齐
    let text_size = data.text_bytes.len() as u64;
    current_offset = text_offset + text_size;
    current_offset = align_to_eight(current_offset);

    // 3. .dynstr段 - 1字节对齐
    let dynstr_offset = current_offset;
    let dynstr_size = 1u64; // 空字符串
    current_offset += dynstr_size;
    current_offset = align_to_eight(current_offset);

    // 4. .dynsym段 - 8字节对齐
    let dynsym_offset = current_offset;
    let dynsym_size = 24u64; // NULL符号
    current_offset += dynsym_size;
    current_offset = align_to_eight(current_offset);

    // 5. .rel.dyn段 - 8字节对齐
    let rel_dyn_offset = current_offset;
    let rel_dyn_size = (data.relocations.len() as u64) * 16; // 每个重定位16字节
    current_offset += rel_dyn_size;
    current_offset = align_to_eight(current_offset);

    // 6. .dynamic段 - 8字节对齐
    let dynamic_offset = current_offset;
    let dynamic_entry_count = 11u64; // 动态条目数量
    let dynamic_size = dynamic_entry_count * 16; // 每个条目16字节
    current_offset += dynamic_size;
    current_offset = align_to_eight(current_offset);

    ElfLayout {
        text_offset,
        text_size,
        dynstr_offset,
        dynstr_size,
        dynsym_offset,
        dynsym_size,
        rel_dyn_offset,
        rel_dyn_size,
        dynamic_offset,
        dynamic_size,
    }
}

/// 构建 SBPF ELF 共享对象文件
pub fn build_sbpf_so(data: &RawSbpfData) -> Result<Vec<u8>, ElfBuildError> {
    // ===== 阶段1: 计算布局 =====
    let mut layout = calculate_layout(data);

    // ===== 阶段2: 生成字节码 =====
    emit_bytecode(data, &mut layout)
}
fn writeHeader(
    writer: &mut Writer,
    data: &RawSbpfData,
    layout: &ElfLayout,
    dynamic_offset: u64,
) -> Result<(), ElfBuildError> {
    // 写入文件头
    writer.write_file_header(&FileHeader {
        os_abi: elf::ELFOSABI_NONE,
        abi_version: 0,
        e_type: elf::ET_DYN,
        e_machine: elf::EM_BPF, // 使用BPF架构匹配示例
        e_entry: 0xe8,
        e_flags: 0,
    })?;
    writer.write_align_program_headers();
    // 写入程序头
    writer.write_program_header(&ProgramHeader {
        p_type: elf::PT_LOAD,
        p_flags: elf::PF_R | elf::PF_X,
        p_offset: 0xe8,
        p_vaddr: 0xe8,
        p_paddr: 0xe8,
        p_filesz: 0x210,
        p_memsz: 0x210,
        p_align: 0x1000,
    });

    writer.write_program_header(&ProgramHeader {
        p_type: elf::PT_LOAD,
        p_flags: elf::PF_R,
        p_offset: 0x398,
        p_vaddr: 0x398,
        p_paddr: 0x398,
        p_filesz: 0x60,
        p_memsz: 0x60,
        p_align: 0x1000,
    });

    writer.write_program_header(&ProgramHeader {
        p_type: elf::PT_DYNAMIC,
        p_flags: elf::PF_R | elf::PF_W,
        p_offset: dynamic_offset as u64,
        p_vaddr: 0x2f8,
        p_paddr: 0x2f8,
        p_filesz: 0xa0,
        p_memsz: 0xa0,
        p_align: 8,
    });

    //let dynsym_offset = writer.reserve_dynsym(); // .dynsym 段
    //let dynstr_offset = writer.reserve_dynstr();

    Ok(())
}
fn write_section(
    writer: &mut Writer,
    data: &RawSbpfData,
    layout: &mut ElfLayout,
    text_index: SectionIndex,
    dynsym_index: SectionIndex,
    rel_dyn_offset: usize,
    name_offset: StringId,
    reldynName: StringId,
) -> Result<(), ElfBuildError> {
    writer.write_null_section_header();
    // .text

    writer.write_section_header(&SectionHeader {
        name: Some(name_offset),
        sh_type: elf::SHT_PROGBITS,
        sh_flags: (elf::SHF_ALLOC | elf::SHF_EXECINSTR) as u64,
        sh_addr: 0xe8,
        sh_offset: layout.text_offset as u64,
        sh_size: data.text_bytes.len() as u64,
        sh_link: 0,
        sh_info: 0,
        sh_addralign: 4,
        sh_entsize: 0,
    });
    // .dynamic
    writer.write_dynamic_section_header(0x2f8);

    // .dynsym
    writer.write_dynsym_section_header(0x398, 1);

    // .dynstr
    writer.write_dynstr_section_header(0x3c8);

    // .rel.dyn

    writer.write_relocation_section_header(
        reldynName,
        text_index,
        dynsym_index,
        rel_dyn_offset,
        2,
        false,
    );

    writer.write_strtab_section_header();
    writer.write_strtab();
    Ok(())

    // .strtab (重命名为 .s)
    //writer.write_strtab_section_header_with_name(0, writer.add_section_name(b".s"));
}
fn write_text(
    writer: &mut Writer,
    data: &RawSbpfData,
    layout: &mut ElfLayout,
) -> Result<(), ElfBuildError> {
    writer.write_align(4);
    //writer.write(&data.text_bytes); // NOP指令填充
    writer.write(&[0x90; 0x210]);
    Ok(())
}
fn write_dynamic(
    writer: &mut Writer,
    data: &RawSbpfData,
    layout: &mut ElfLayout,
    sol_log: StringId,
) -> Result<(), ElfBuildError> {
    // 3. 添加动态字符串
    //writer.reserve_dynsym();
    writer.write_null_dynamic_symbol();
    writer.write_dynamic_symbol(&Sym {
        name: Some(sol_log),
        section: None,
        st_info: elf::STB_GLOBAL | elf::STT_NOTYPE,
        st_other: elf::STV_DEFAULT,
        st_shndx: elf::SHN_UNDEF,
        st_value: 0,
        st_size: 0,
    });

    // 13. 写入动态字符串
    writer.write_dynstr();
    Ok(())
}

/// 生成最终的 ELF 字节码
fn emit_bytecode(data: &RawSbpfData, layout: &mut ElfLayout) -> Result<Vec<u8>, ElfBuildError> {
    // 使用正确的ELF Writer API
    let mut buffer = Vec::new();
    //buffer.resize(8000 *2 as usize, 0);
    let mut writer = Writer::new(Endianness::Little, true, &mut buffer);
    writer.reserve_file_header();
    writer.reserve_program_headers(3);
    writer.reserve_strtab_section_index_with_name(b".s");
    let name_offset = writer.add_section_name(b".text");
    let reldynName = writer.add_section_name(b".rel.dyn");

    // 2. 预留所有段索引
    let text_index = writer.reserve_section_index();
    eprintln!("text_index {:?}", text_index);
    let dynamic_index = writer.reserve_dynamic_section_index();
    let dynsym_index = writer.reserve_dynsym_section_index();

    let dynstr_index = writer.reserve_dynstr_section_index();
    let rel_dyn_index = writer.reserve_section_index();
    //let strtab_index = writer.reserve_strtab_section_index();

    let null_dynsym = writer.reserve_null_dynamic_symbol_index();
    let sol_log_sym = writer.reserve_dynamic_symbol_index();
    let sol_log = writer.add_dynamic_string(b"sol_log_");

    eprintln!("text code :{:0x}", data.text_bytes.len());
    let text_offset = writer.reserve(data.text_bytes.len(), 4);
    eprintln!("text_offset :{:0x}", text_offset);
    let dynamic_offset = writer.reserve_dynamic(11);
    eprintln!("dynamic_offset :{}", dynamic_offset);
    let dynsym_offset = writer.reserve_dynsym();
    eprintln!("dynsym_offset :{}", dynsym_offset);

    let dynstr_offset = writer.reserve_dynstr();
    eprintln!("dynstr_offset :{:?}", dynstr_offset);
    //writer.reserve_strtab_section_index_with_name(b".s");

    let strtab_offset = writer.reserve_strtab();
    eprintln!("strtab_offset :{:?}", strtab_offset);

    let rel_dyn_offset = writer.reserve_relocations(2, false);
    eprintln!("rel_dyn_offset :{:?}", rel_dyn_offset);

    writer.reserve_shstrtab();
    writer.reserve_section_headers();

    writeHeader(&mut writer, data, layout, dynamic_offset as u64)?;

    write_text(&mut writer, data, layout)?;

    //
    //let dynamic_offset = writer.reserve_dynamic(10);
    //eprintln!("dynamic_offset :{}", dynamic_offset);
    //writer.reserve_dynamics(dynamic_num)
    //
    //writer.reserve_dynamic(12);

    //writer.reserve(writer.reserved_len())?;

    writer.write_align_dynamic();

    writer.write_strtab();

    writer.write_dynamic(elf::DT_FLAGS, elf::DF_TEXTREL as u64);
    writer.write_dynamic(elf::DT_REL, 0x3d8);
    writer.write_dynamic(elf::DT_RELSZ, 32);
    writer.write_dynamic(elf::DT_RELENT, 16);
    writer.write_dynamic(elf::DT_RELCOUNT, 2);
    writer.write_dynamic(elf::DT_SYMTAB, 0x398);
    writer.write_dynamic(elf::DT_SYMENT, 24);
    writer.write_dynamic(elf::DT_STRTAB, 0x3c8);
    writer.write_dynamic(elf::DT_STRSZ, 16);
    writer.write_dynamic(elf::DT_TEXTREL, 0);
    writer.write_dynamic(elf::DT_NULL, 0);
    //writer.write_symbol()

    write_dynamic(&mut writer, data, layout, sol_log)?;

    eprintln!("rel_dyn_offset {:?}", rel_dyn_offset);
    writer.write_align_relocation();
    writer.write_relocation(
        false,
        &Rel {
            r_offset: 0x1b0,
            r_sym: 1,
            r_type: elf::R_BPF_64_32,
            r_addend: 0,
        },
    );
    writer.write_relocation(
        false,
        &Rel {
            r_offset: 0x2e8,
            r_sym: 1,
            r_type: elf::R_BPF_64_32,
            r_addend: 0,
        },
    );
    //writer.reserve_strtab_section_index_with_name(b".s");
    writer.write_shstrtab();

    // 14. 写入重定位

    write_section(
        &mut writer,
        data,
        layout,
        text_index,
        dynamic_index,
        rel_dyn_offset,
        name_offset,
        reldynName,
    )?;

    Ok(buffer.to_vec())
}
