/// Murmur3_32 哈希函数实现（常量时间）
///
/// 根据 SBPF V0 规范，syscall 指令的 immediate 字段必须是
/// syscall 名称的 murmur3_32 哈希值
pub const fn murmur3_32(buf: &[u8]) -> u32 {
    const fn pre_mix(buf: [u8; 4]) -> u32 {
        u32::from_le_bytes(buf)
            .wrapping_mul(0xcc9e2d51)
            .rotate_left(15)
            .wrapping_mul(0x1b873593)
    }

    let mut hash = 0;
    let mut i = 0;

    while i < buf.len() / 4 {
        let buf = [buf[i * 4], buf[i * 4 + 1], buf[i * 4 + 2], buf[i * 4 + 3]];
        hash ^= pre_mix(buf);
        hash = hash.rotate_left(13);
        hash = hash.wrapping_mul(5).wrapping_add(0xe6546b64);
        i += 1;
    }

    match buf.len() % 4 {
        0 => {}
        1 => {
            hash = hash ^ pre_mix([buf[i * 4], 0, 0, 0]);
        }
        2 => {
            hash = hash ^ pre_mix([buf[i * 4], buf[i * 4 + 1], 0, 0]);
        }
        3 => {
            hash = hash ^ pre_mix([buf[i * 4], buf[i * 4 + 1], buf[i * 4 + 2], 0]);
        }
        _ => unreachable!(),
    }

    // 最终的混合
    hash ^= buf.len() as u32;
    hash ^= hash >> 16;
    hash = hash.wrapping_mul(0x85ebca6b);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(0xc2b2ae35);
    hash ^= hash >> 16;
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_murmur3_32_sol_log() {
        // 测试 sol_log_ 的哈希值
        let hash = murmur3_32(b"sol_log_");
        println!("murmur3_32('sol_log_') = 0x{:08x}", hash);
        // 这个值应该与 SBPF 规范一致
    }

    #[test]
    fn test_murmur3_32_empty() {
        // 测试空字符串
        let hash = murmur3_32(b"");
        assert_eq!(hash, 0);
    }

    #[test]
    fn test_murmur3_32_single_byte() {
        // 测试单字节
        let hash = murmur3_32(b"a");
        assert_ne!(hash, 0);
    }
}