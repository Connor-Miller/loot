//! Byte <-> hex conversion, shared across the workspace.
//!
//! One home for a conversion that was previously re-implemented in the CLI,
//! the persistence codec, and the relay. Lowercase, two chars per byte. Kept
//! deliberately tiny and dependency-free: content addresses, pubkeys, and
//! mailbox names are the only things loot ever hex-encodes.

/// Lowercase hex string of `bytes` (two chars per byte).
pub fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

/// Decode a hex string into bytes. `None` on odd length or a non-hex char.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

/// Decode exactly `N` bytes of hex (2·N chars). `None` on wrong length or a
/// non-hex char. The workhorse for fixed-width content addresses and pubkeys.
pub fn decode_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let v = decode(s)?;
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    Some(out)
}

/// The first `n` bytes as hex — a short prefix for display. No ellipsis; the
/// caller adds one if it wants (some call sites do, some don't).
pub fn short(bytes: &[u8], n: usize) -> String {
    encode(&bytes[..n.min(bytes.len())])
}

/// Render `bytes` as **reverse-hex letters** (ADR 0029): each nibble `0..=15`
/// maps to `k l m n o p q r s t u v w x y z`, e.g. `qsouzmpr`. This is jj's
/// convention for the durable **change id**, deliberately a different alphabet
/// from the version id's hex **digits** (`encode`/`short`) so a reader never has
/// to ask which id they are looking at — the letters *are* the disambiguation.
pub fn letters(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push((b'k' + (b >> 4)) as char);
        s.push((b'k' + (b & 0xf)) as char);
    }
    s
}

/// The first `n` bytes as reverse-hex letters — a short change-id prefix for
/// display (ADR 0029), the letter twin of [`short`].
pub fn short_letters(bytes: &[u8], n: usize) -> String {
    letters(&bytes[..n.min(bytes.len())])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let bytes = [0u8, 1, 15, 16, 127, 128, 255, 0xab];
        let s = encode(&bytes);
        assert_eq!(s, "00010f107f80ffab");
        assert_eq!(decode(&s).unwrap(), bytes);
    }

    #[test]
    fn decode_rejects_bad_input() {
        assert!(decode("abc").is_none(), "odd length");
        assert!(decode("zz").is_none(), "non-hex");
    }

    #[test]
    fn decode_array_is_length_checked() {
        let arr = [9u8; 32];
        let s = encode(&arr);
        assert_eq!(decode_array::<32>(&s), Some(arr));
        assert_eq!(decode_array::<32>("00"), None, "too short");
        assert_eq!(decode_array::<32>(&format!("{s}00")), None, "too long");
    }

    #[test]
    fn short_takes_a_prefix() {
        assert_eq!(short(&[0xde, 0xad, 0xbe, 0xef, 0x00], 2), "dead");
        assert_eq!(short(&[0x01], 4), "01", "clamps to len");
    }

    #[test]
    fn letters_map_nibbles_to_k_through_z() {
        // 0x0 -> 'k', 0xf -> 'z'; letters are the reverse-hex change-id alphabet.
        assert_eq!(letters(&[0x0f]), "kz");
        assert_eq!(letters(&[0x00, 0xff]), "kkzz");
        // Every nibble stays inside k..=z (16 letters), never a digit.
        assert!(letters(&[0xAB, 0xCD, 0xEF]).chars().all(|c| ('k'..='z').contains(&c)));
        assert_eq!(short_letters(&[0xde, 0xad, 0xbe, 0xef], 2), letters(&[0xde, 0xad]));
    }
}
