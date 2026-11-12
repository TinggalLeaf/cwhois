// whois 响应结构化解析：把行序列解析为「对象 → 键值对/原始行」。
// 解析失败的内容一律保留为原始行，保证信息零丢失。

#[derive(Debug, Clone)]
pub enum Line {
    /// 键值对；value 中可能含 '\n' 连接的续行
    Pair { key: String, value: String },
    /// 注释/横幅等原始行
    Raw(String),
}

#[derive(Debug)]
pub struct Object {
    pub lines: Vec<Line>,
}

impl Object {
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// 首个键值对的键（小写）
    pub fn primary_key(&self) -> Option<&str> {
        self.lines.iter().find_map(|l| match l {
            Line::Pair { key, .. } => Some(key.as_str()),
            _ => None,
        })
    }

    /// 取指定键（大小写不敏感）的第一个值
    pub fn get(&self, key: &str) -> Option<&str> {
        self.lines.iter().find_map(|l| match l {
            Line::Pair { key: k, value } if k.eq_ignore_ascii_case(key) => Some(value.as_str()),
            _ => None,
        })
    }
}

#[derive(Debug)]
pub struct Parsed {
    pub objects: Vec<Object>,
}

/// 判断一行是否为 "Key: value" 形式；返回 (key, value)。
fn split_pair(line: &str) -> Option<(String, String)> {
    let bytes = line.as_bytes();
    // 允许前导空白（verisign 记录用 3 个空格缩进键名）
    let mut i = 0;
    let mut leading = 0;
    while i < bytes.len() && bytes[i] == b' ' {
        i += 1;
        leading += 1;
    }
    // 键必须以字母开头
    if i >= bytes.len() || !bytes[i].is_ascii_alphabetic() {
        return None;
    }
    let key_start = i;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b' ' | b'-' | b'/' | b'_')) {
        i += 1;
    }
    let key = &line[key_start..i];
    // 键后必须紧跟冒号
    if i >= bytes.len() || bytes[i] != b':' {
        return None;
    }
    // 键不能太长（避免把一句话误判为键）
    if key.len() > 40 {
        return None;
    }
    // 冒号后必须是空白或行尾
    let after = &line[i + 1..];
    if !after.is_empty() && !after.starts_with([' ', '\t']) {
        return None;
    }
    // 前导空白行：要求缩进 ≤ 8 且是 verisign 风格（防御续行误判）
    if leading > 0 && leading > 8 {
        return None;
    }
    let value = after.trim_start_matches([' ', '\t']);
    Some((key.to_string(), value.to_string()))
}

pub fn parse(lines: &[String]) -> Parsed {
    let mut objects: Vec<Object> = Vec::new();
    let mut cur = Object { lines: Vec::new() };
    let mut last_pair: Option<usize> = None; // cur.lines 中最近 Pair 的下标

    for line in lines {
        if line.is_empty() {
            if !cur.lines.is_empty() {
                objects.push(std::mem::replace(&mut cur, Object { lines: Vec::new() }));
            }
            last_pair = None;
            continue;
        }
        if let Some((key, value)) = split_pair(line) {
            cur.lines.push(Line::Pair { key: key.to_lowercase(), value });
            last_pair = Some(cur.lines.len() - 1);
        } else if line.starts_with([' ', '\t']) || line.starts_with(['%', '#', ';']) {
            // 续行或注释
            if line.starts_with([' ', '\t']) {
                if let Some(idx) = last_pair {
                    if let Line::Pair { value, .. } = &mut cur.lines[idx] {
                        value.push('\n');
                        value.push_str(line.trim());
                        continue;
                    }
                }
            }
            cur.lines.push(Line::Raw(line.clone()));
        } else {
            cur.lines.push(Line::Raw(line.clone()));
        }
    }
    if !cur.lines.is_empty() {
        objects.push(cur);
    }
    Parsed { objects }
}

/// 对象类型推断（用于卡片标题徽章）。
pub fn object_type(obj: &Object) -> &'static str {
    match obj.primary_key().unwrap_or("") {
        "domain name" | "domain" | "domain-handle" => "域名",
        "netrange" | "inetnum" => "IPv4 网络",
        "inet6num" => "IPv6 网络",
        "aut-num" | "as-number" => "自治系统",
        "route" => "路由",
        "route6" => "IPv6 路由",
        "as-set" | "as-block" => "AS 集合",
        "person" => "联系人",
        "role" => "角色",
        "organisation" | "org" | "organization" | "org-name" => "组织",
        "netname" => "网络",
        "server name" => "域名服务器",
        "poem" => "诗文",
        "irt" => "IRT 团队",
        "mntner" => "维护者",
        "key-cert" | "pgpkey" => "密钥证书",
        "domain type" | "nserver" => "域名",
        _ => "记录",
    }
}

/// 卡片标题：优先取有代表性的键值。
pub fn object_title(obj: &Object) -> Option<String> {
    const KEYS: &[&str] = &[
        "domain name", "domain", "netname", "org-name", "organisation", "person", "role",
        "as-name", "aut-num", "netrange", "inetnum", "inet6num", "route", "route6",
        "server name", "nic-hdl", "mntner", "descr",
    ];
    for k in KEYS {
        if let Some(v) = obj.get(k) {
            let v = v.lines().next().unwrap_or("").trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}
