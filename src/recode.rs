// 字符集转码：把 whois 服务器的非 UTF-8 输出转换为 UTF-8。
// 支持 iso-8859-1、cp1251、iso-2022-jp（仅去除转义序列，保持 ASCII 内容）。

pub fn to_utf8(raw: &[u8], charset: &str) -> String {
    match charset {
        "iso-8859-1" | "latin1" | "latin-1" => latin1_to_utf8(raw),
        "cp1251" => cp1251_to_utf8(raw),
        "iso-2022-jp" => iso2022jp_to_utf8(raw),
        // utf-8 与未知：直接按 UTF-8 解释（损失替换）
        _ => String::from_utf8_lossy(raw).into_owned(),
    }
}

fn latin1_to_utf8(raw: &[u8]) -> String {
    raw.iter()
        .map(|&b| match b {
            0x00..=0x7f => b as char,
            _ => char::from_u32(b as u32).unwrap_or('\u{fffd}'),
        })
        .collect()
}

fn cp1251_to_utf8(raw: &[u8]) -> String {
    // Windows-1251 → Unicode（0x80-0xFF 映射表）
    const TABLE: [u32; 128] = [
        0x0402, 0x0403, 0x201A, 0x0453, 0x201E, 0x2026, 0x2020, 0x2021, // 80-87
        0x20AC, 0x2030, 0x0409, 0x2039, 0x040A, 0x040C, 0x040B, 0x040F, // 88-8F
        0x0452, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, // 90-97
        0x0098, 0x2122, 0x0459, 0x203A, 0x045A, 0x045C, 0x045B, 0x045F, // 98-9F
        0x00A0, 0x040E, 0x045E, 0x0408, 0x00A4, 0x0490, 0x00A6, 0x00A7, // A0-A7
        0x0401, 0x00A9, 0x0404, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x0407, // A8-AF
        0x00B0, 0x00B1, 0x0406, 0x0456, 0x0491, 0x00B5, 0x00B6, 0x00B7, // B0-B7
        0x0451, 0x2116, 0x0454, 0x00BB, 0x0458, 0x0405, 0x0455, 0x0457, // B8-BF
        0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417, // C0-C7
        0x0418, 0x0419, 0x041A, 0x041B, 0x041C, 0x041D, 0x041E, 0x041F, // C8-CF
        0x0420, 0x0421, 0x0422, 0x0423, 0x0424, 0x0425, 0x0426, 0x0427, // D0-D7
        0x0428, 0x0429, 0x042A, 0x042B, 0x042C, 0x042D, 0x042E, 0x042F, // D8-DF
        0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437, // E0-E7
        0x0438, 0x0439, 0x043A, 0x043B, 0x043C, 0x043D, 0x043E, 0x043F, // E8-EF
        0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447, // F0-F7
        0x0448, 0x0449, 0x044A, 0x044B, 0x044C, 0x044D, 0x044E, 0x044F, // F8-FF
    ];
    let mut out = String::with_capacity(raw.len());
    for &b in raw {
        match b {
            0x00..=0x7f => out.push(b as char),
            _ => out.push(char::from_u32(TABLE[(b - 0x80) as usize]).unwrap_or('\u{fffd}')),
        }
    }
    out
}

fn iso2022jp_to_utf8(raw: &[u8]) -> String {
    // 完整 JIS→Unicode 需要大映射表；whois 场景中日文服务器在
    // 非日语环境会附加 /e 返回英文，因此这里仅去除转义序列、保留 ASCII。
    // ESC 序列 = ESC + 中间字节(0x20-0x2F)* + 最终字节(0x30-0x7E)
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == 0x1b {
            i += 1;
            while i < raw.len() && (0x20..=0x2f).contains(&raw[i]) {
                i += 1;
            }
            if i < raw.len() {
                i += 1; // 最终字节
            }
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    // 非 ASCII 字节按 UTF-8 损失解释（基本是日文移位码，无法无表转换）
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latin1() {
        assert_eq!(to_utf8(b"caf\xe9", "iso-8859-1"), "caf\u{e9}");
    }

    #[test]
    fn cp1251_basic() {
        // "Привет" in cp1251
        let bytes = [0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2];
        assert_eq!(to_utf8(&bytes, "cp1251"), "\u{41f}\u{440}\u{438}\u{432}\u{435}\u{442}");
    }

    #[test]
    fn iso2022jp_escapes() {
        let bytes = b"\x1b$B\x1b(Bhello";
        assert_eq!(iso2022jp_to_utf8(bytes), "hello");
    }
}
