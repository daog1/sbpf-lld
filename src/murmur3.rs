/// Murmur3_32 hash function implementation (constant time)
///
/// According to SBPF V0 specification, the immediate field of syscall instructions
/// must be the murmur3_32 hash value of the syscall name
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

    // Final mixing
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
        // Test hash value of sol_log_
        let hash = murmur3_32(b"sol_log_");
        println!("murmur3_32('sol_log_') = 0x{:08x}", hash);
        // This value should be consistent with SBPF specification
    }

    #[test]
    fn test_murmur3_32_empty() {
        // Test empty string
        let hash = murmur3_32(b"");
        assert_eq!(hash, 0);
    }

    #[test]
    fn test_murmur3_32_single_byte() {
        // Test single byte
        let hash = murmur3_32(b"a");
        assert_ne!(hash, 0);
    }
}
