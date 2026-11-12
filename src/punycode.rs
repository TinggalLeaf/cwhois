// Punycode 编码（RFC 3492），用于将 IDN 域名的非 ASCII 标签转换为 xn-- 形式。
// 仅实现编码方向（whois 客户端只需要编码查询词）。

const BASE: u32 = 36;
const TMIN: u32 = 1;
const TMAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: u32 = 128;

fn adapt(delta: u32, numpoints: u32, firsttime: bool) -> u32 {
    let mut delta = if firsttime { delta / DAMP } else { delta / 2 };
    delta += delta / numpoints;
    let mut k = 0;
    while delta > ((BASE - TMIN) * TMAX) / 2 {
        delta /= BASE - TMIN;
        k += BASE;
    }
    k + (BASE - TMIN + 1) * delta / (delta + SKEW)
}

fn encode_digit(d: u32) -> char {
    // 0..25 -> 'a'..'z', 26..35 -> '0'..'9'
    let c = match d {
        0..=25 => (b'a' + d as u8) as char,
        _ => (b'0' + (d as u8 - 26)) as char,
    };
    c
}

/// 将单个标签（不含点）编码为 punycode（不含 xn-- 前缀）。
/// 输入为 Unicode 标量序列；若全部为 ASCII 则原样返回（调用方处理小写）。
pub fn encode_label(label: &str) -> Option<String> {
    let chars: Vec<char> = label.chars().collect();
    if chars.iter().all(|&c| (c as u32) < 0x80) {
        return Some(label.to_string());
    }

    let mut out = String::new();
    // 先输出所有基本码点（ASCII）
    let mut n = INITIAL_N;
    let mut delta: u32 = 0;
    let mut bias = INITIAL_BIAS;
    let mut b: u32 = 0; // 基本码点数量
    for &c in &chars {
        if (c as u32) < 0x80 {
            out.push(c);
            b += 1;
        }
    }
    let mut h = b;
    if b > 0 {
        out.push('-');
    }

    let total = chars.len() as u32;
    while h < total {
        // 找到大于等于 n 的最小编码点
        let mut m = u32::MAX;
        for &c in &chars {
            let cp = c as u32;
            if cp >= n && cp < m {
                m = cp;
            }
        }
        if m == u32::MAX {
            return None; // 不应该发生
        }
        delta = delta.checked_add((m - n) * (h + 1))?;
        n = m;
        for &c in &chars {
            let cp = c as u32;
            if cp < n {
                delta = delta.checked_add(1)?;
            } else if cp == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias {
                        TMIN
                    } else if k >= bias + TMAX {
                        TMAX
                    } else {
                        k - bias
                    };
                    if q < t {
                        break;
                    }
                    out.push(encode_digit(t + (q - t) % (BASE - t)));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                out.push(encode_digit(q));
                bias = adapt(delta, h + 1, h == b);
                delta = 0;
                h += 1;
            }
        }
        delta = delta.checked_add(1)?;
        n = n.checked_add(1)?;
    }
    Some(out)
}

/// 将完整域名（允许含中文等非 ASCII 字符）转换为 ACE (xn--) 形式。
/// 每个标签独立编码；ASCII 标签转小写。失败时返回原始输入的小写形式。
pub fn domain_to_ascii(domain: &str) -> String {
    domain
        .split('.')
        .map(|label| {
            let lower: String = label.chars().flat_map(|c| c.to_lowercase()).collect();
            if lower.is_empty() {
                return lower;
            }
            if lower.chars().all(|c| (c as u32) < 0x80) {
                return lower;
            }
            match encode_label(&lower) {
                Some(puny) => format!("xn--{}", puny),
                None => lower,
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3492_examples() {
        // RFC 3492 / IDNA 标准测试向量
        assert_eq!(encode_label("bücher").unwrap(), "bcher-kva");
        assert_eq!(encode_label("mañana").unwrap(), "maana-pta");
        assert_eq!(encode_label("résumé").unwrap(), "rsum-bpad");
        assert_eq!(encode_label("例え").unwrap(), "r8jz45g");
        assert_eq!(encode_label("ドメイン").unwrap(), "eckwd4c7c");
    }

    #[test]
    fn chinese_domain() {
        // "中国" 的 punycode 是 "fiqs8s"
        let ace = domain_to_ascii("中国.cn");
        assert_eq!(ace, "xn--fiqs8s.cn");
        let ace2 = domain_to_ascii("例子.中国");
        assert_eq!(ace2, "xn--fsqu00a.xn--fiqs8s");
    }

    #[test]
    fn ascii_passthrough() {
        assert_eq!(domain_to_ascii("Example.COM"), "example.com");
        assert_eq!(domain_to_ascii("www.bbc.co.uk"), "www.bbc.co.uk");
    }
}
