// whois 协议引擎 —— 忠实移植 whois（rfc1036/whois）whois.c 的行为：
// 服务器猜测、查询串构造、引荐跟踪、递归查询、免责声明隐藏。

use crate::data;
use crate::punycode;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub const DEFAULT_SERVER: &str = "whois.arin.net";
pub const CLIENT_TAG: &str = "MDcwhois0.1";

/// 查询过程中产生的事件，供渲染层消费。
#[derive(Debug)]
pub enum Event {
    /// 提示信息（网页查询地址、未知对象类型等）
    Message(String),
    /// 跟踪到引荐服务器
    ReferralBanner(String),
    /// 6to4 / Teredo 提示
    Notice(String),
    /// --verbose 诊断信息
    Verbose(String),
    /// 错误信息（输出到 stderr，对应 whois 的 err_sys/err_quit）
    Error(String),
    /// 一次服务器响应
    Response(Response),
}

#[derive(Debug)]
pub struct Response {
    pub server: String,
    pub query: String,
    pub lines: Vec<String>,
    pub referral: Option<String>,
}

/// 运行选项（程序级参数）
pub struct Opts {
    pub verbose: bool,
    pub no_recursion: bool,
    pub hide_disclaimers: bool,
    pub client_tag: String,
}

// ---------------------------------------------------------------------------
// 基础判定

/// 判断字符串是否为 "ASnnnn" 或 "AS nnnn" 形式的自治系统号。
pub fn is_asn(s: &str, allow_space: bool, suffix_separators: Option<&str>) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() < 2 || !s[..2].eq_ignore_ascii_case("as") {
        return false;
    }
    let mut p = 2;
    if allow_space && bytes.get(p) == Some(&b' ') {
        p += 1;
    }
    let mut seen_number = false;
    let mut max_numbers = 6;
    while let Some(&c) = bytes.get(p) {
        if !c.is_ascii_digit() {
            if !seen_number {
                return false;
            }
            if let Some(seps) = suffix_separators {
                if seps.contains(c as char) {
                    return true;
                }
            }
            return false;
        }
        seen_number = true;
        max_numbers -= 1;
        if max_numbers == 0 {
            return false;
        }
        p += 1;
    }
    seen_number
}

/// 解析 "a.b.c.d" 或 "a.b.c.d/mask" 形式的 IPv4 地址为 u32。
pub fn myinet_aton(s: &str) -> Option<u32> {
    let ip_part = s.split('/').next().unwrap_or(s);
    let octets: Vec<&str> = ip_part.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    let mut v: u32 = 0;
    for o in octets {
        if o.is_empty() || o.len() > 3 {
            return None;
        }
        let n: u32 = o.parse().ok()?;
        if n > 255 {
            return None;
        }
        v = (v << 8) | n;
    }
    // 与 C 的 sscanf 一致：允许尾随 / 掩码，其他尾随垃圾拒绝
    match s.split('/').nth(1) {
        Some(_) => {
            if s.matches('/').count() == 1 {
                Some(v)
            } else {
                None
            }
        }
        None => Some(v),
    }
}

/// 根据 ASN 查询归属 RIR（先匹配优先）。
pub fn whereas(asn: u32) -> &'static str {
    for &(first, last, serv) in data::AS_ASSIGN {
        if asn >= first && asn <= last {
            return serv;
        }
    }
    "\u{6}"
}

/// dom 是否以 ".tld" 结尾（tld 本身不含点）。
pub fn in_domain(dom: &str, tld: &str) -> bool {
    let dom_len = dom.len();
    let tld_len = tld.len();
    if dom_len == 0 || tld_len == 0 || tld_len as isize >= dom_len as isize - 1 {
        return false;
    }
    let p = &dom[dom_len - tld_len..];
    dom.as_bytes()[dom_len - tld_len - 1] == b'.' && p.eq_ignore_ascii_case(tld)
}

/// dom 是否以 tld 结尾（允许直接相接）。
pub fn endstrcaseeq(dom: &str, tld: &str) -> bool {
    let dom_len = dom.len();
    let tld_len = tld.len();
    if dom_len == 0 || tld_len == 0 || tld_len > dom_len {
        return false;
    }
    dom[dom_len - tld_len..].eq_ignore_ascii_case(tld)
}

/// 查询是否属于某个新 gTLD；返回该 gTLD。
pub fn is_new_gtld(s: &str) -> Option<&'static str> {
    data::new_gtlds().iter().copied().find(|g| in_domain(s, g))
}

// ---------------------------------------------------------------------------
// 服务器猜测（返回编码串，首字符 < 0x20 表示特殊处理）

pub fn guess_server(s: &str) -> String {
    // IPv6 地址
    if s.contains(':') {
        if is_asn(s, false, Some(":")) {
            let digits: String = s[2..].chars().take_while(|c| c.is_ascii_digit()).collect();
            let asn: u32 = digits.parse().unwrap_or(0);
            return whereas(asn).to_string();
        }
        let hex = |t: &str| u32::from_str_radix(t, 16).unwrap_or(0);
        let v6prefix = hex(s.split(':').next().unwrap_or(""));
        if v6prefix == 0 {
            return "\u{5}".to_string();
        }
        let v6net = (v6prefix << 16).wrapping_add(hex(s.split(':').nth(1).unwrap_or("")));
        for &(net, masklen, serv) in data::IP6_ASSIGN {
            let mask: u32 = if masklen >= 32 { u32::MAX } else { u32::MAX << (32 - masklen) };
            if v6net & mask == net {
                return serv.to_string();
            }
        }
        return "\u{6}".to_string();
    }

    // 邮箱地址
    if s.contains('@') {
        return "\u{5}".to_string();
    }

    // 无点：TLD 或新 gTLD → IANA
    if !s.contains('.') {
        for &(tld, _) in data::TLD_SERV {
            if s.eq_ignore_ascii_case(tld) {
                return "whois.iana.org".to_string();
            }
        }
        for g in data::new_gtlds() {
            if s.eq_ignore_ascii_case(g) {
                return "whois.iana.org".to_string();
            }
        }
    }

    // 无点且无连字符：NSI NIC 句柄或 ASN
    if !s.contains('.') && !s.contains('-') {
        if is_asn(s, true, None) {
            let asn: u32 = s[2..].trim_start().parse().unwrap_or(0);
            return whereas(asn).to_string();
        }
        if s.starts_with('!') {
            return "whois.networksolutions.com".to_string();
        }
        return "\u{5}".to_string();
    }

    // 看起来像 IPv4？
    if let Some(ip) = myinet_aton(s) {
        for e in data::ip4_table() {
            if ip & e.1 == e.0 {
                return e.2.to_string();
            }
        }
        return "\u{5}".to_string();
    }

    // TLD 表
    for &(tld, serv) in data::TLD_SERV {
        if in_domain(s, tld) {
            return serv.to_string();
        }
    }

    // 新 gTLD 默认服务器
    if let Some(g) = is_new_gtld(s) {
        return format!("whois.nic.{}", g);
    }

    // 无点但有连字符：NIC 句柄
    if !s.contains('.') {
        for &(prefix, serv) in data::NIC_HANDLES {
            if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
                return serv.to_string();
            }
        }
        for &(postfix, serv) in data::NIC_HANDLES_POST {
            if endstrcaseeq(s, postfix) {
                return serv.to_string();
            }
        }
        // 可能是网络名 → 默认服务器
        return String::new();
    }

    "\u{5}".to_string()
}

// ---------------------------------------------------------------------------
// 域名规范化：去尾部点/空白，最后一个词做 punycode。

pub fn normalize_domain(dom: &str) -> String {
    let trimmed = dom.trim_end_matches(['.', ' ', '\t']);
    if trimmed.starts_with('!') {
        return trimmed.to_string();
    }
    match trimmed.rfind(' ') {
        Some(idx) => {
            let (prefix, word) = trimmed.split_at(idx + 1);
            format!("{}{}", prefix, punycode::domain_to_ascii(word))
        }
        None => punycode::domain_to_ascii(trimmed),
    }
}

// ---------------------------------------------------------------------------
// 服务器名拆分（host:port / [v6]:port）

pub fn split_server_port(input: &str) -> (String, Option<String>) {
    if let Some(rest) = input.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = &rest[..end];
            let port = rest[end + 1..].strip_prefix(':').filter(|p| !p.is_empty());
            return (host.to_lowercase(), port.map(String::from));
        }
    }
    match input.rsplit_once(':') {
        Some((host, port)) if !port.contains(':') && !host.contains(':') => {
            (host.to_lowercase(), Some(port.to_string()))
        }
        _ => (input.to_lowercase(), None),
    }
}

// ---------------------------------------------------------------------------
// 查询串构造

fn japanese_locale() -> bool {
    for var in ["LC_MESSAGES", "LC_ALL", "LANG"] {
        if let Ok(v) = std::env::var(var) {
            return v.to_lowercase().starts_with("ja");
        }
    }
    false
}

/// 服务器输出字符集与附加查询参数。
pub fn charset_for(server: &str, query: &str) -> (&'static str, &'static str) {
    for &(name, cs, o) in data::SERVERS_CHARSET {
        if name == server {
            return (cs, o);
        }
    }
    if !query.contains(' ') && is_new_gtld(query).is_some() {
        return ("utf-8", "");
    }
    ("", "")
}

/// 构造发送给服务器的查询串。
pub fn queryformat(server: &str, flags: &str, query: &str, client_tag: &str) -> String {
    let mut buf = String::new();
    let isripe = data::RIPE_SERVERS.iter().any(|&s| s == server);
    if isripe {
        buf.push_str("-V ");
        buf.push_str(client_tag);
        buf.push(' ');
    }

    if !flags.is_empty() {
        if !isripe {
            println!("警告: 对传统服务器使用了 RIPE 标志。");
        }
        buf.push_str(flags);
    }

    let (_cs, opts) = charset_for(server, query);
    if !opts.is_empty() {
        buf.push_str(opts);
        buf.push(' ');
    }

    // 服务器特定的默认标志
    if !isripe && !query.contains(' ') && flags.is_empty() {
        if server == "whois.denic.de" && in_domain(query, "de") {
            buf.push_str("-T dn,ace ");
        } else if (server == "whois.punktum.dk" || server == "whois.dk-hostmaster.dk")
            && in_domain(query, "dk")
        {
            buf.push_str("--show-handles ");
        }
    }

    // 查询词变形
    if !isripe && server == "whois.nic.ad.jp" && is_asn(query, true, None) {
        buf.push_str("AS ");
        buf.push_str(query[2..].trim_start());
    } else if !isripe && server == "whois.arin.net" && !query.contains(' ') {
        if is_asn(query, false, None) {
            buf.push_str("a ");
            buf.push_str(&query[2..]);
        } else if myinet_aton(query).is_some() || query.contains(':') {
            if query.contains('/') {
                buf.push_str("r + = ");
            } else {
                buf.push_str("n + ");
            }
            buf.push_str(query);
        } else {
            buf.push_str(query);
        }
    } else {
        buf.push_str(query);
    }

    // 日语服务器：非日语环境请求英文输出
    if !isripe
        && (server == "whois.nic.ad.jp" || server == "whois.jprs.jp")
        && !japanese_locale()
        && !buf.ends_with("/e")
    {
        buf.push_str("/e");
    }

    buf
}

// ---------------------------------------------------------------------------
// 免责声明隐藏状态机

const HIDE_TO_THE_END: i32 = -3;
const HIDE_DISABLED: i32 = -2;
const HIDE_NOT_STARTED: i32 = -1;

struct HideState {
    state: i32,
}

impl HideState {
    fn new(enabled: bool) -> Self {
        HideState {
            state: if enabled { HIDE_NOT_STARTED } else { HIDE_DISABLED },
        }
    }

    fn hide_line(&mut self, line: &str) -> bool {
        if self.state == HIDE_TO_THE_END {
            true
        } else if self.state == HIDE_DISABLED {
            false
        } else if self.state == HIDE_NOT_STARTED {
            for (i, (start, _)) in data::HIDE_STRINGS.iter().enumerate() {
                if line.starts_with(start) {
                    self.state = match data::HIDE_STRINGS[i].1 {
                        None => HIDE_TO_THE_END,
                        Some(_) => i as i32,
                    };
                    return true;
                }
            }
            false
        } else {
            let i = self.state as usize;
            match data::HIDE_STRINGS[i].1 {
                Some(end) if end.is_empty() => {
                    if line.is_empty() {
                        self.state = HIDE_NOT_STARTED;
                        false
                    } else {
                        true
                    }
                }
                Some(end) => {
                    if line.starts_with(end) {
                        self.state = HIDE_NOT_STARTED;
                    }
                    true
                }
                None => true,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 引荐服务器跟踪

#[derive(Clone, Copy, PartialEq)]
pub enum ReferralKind {
    None,
    Apnic,
    Arin,
    Iana,
    Verisign,
    Recursive,
}

pub fn referral_kind_for(server: &str) -> ReferralKind {
    match server {
        "whois.apnic.net" => ReferralKind::Apnic,
        "whois.arin.net" => ReferralKind::Arin,
        "whois.iana.org" => ReferralKind::Iana,
        _ => ReferralKind::None,
    }
}

struct ApnicFsm {
    state: u8,
    rir_name: Option<String>,
}

impl ApnicFsm {
    fn new() -> Self {
        ApnicFsm { state: 0, rir_name: None }
    }
    fn feed(&mut self, buf: &str, referral: &mut Option<String>) {
        if self.state == 4 {
            return;
        }
        if self.state <= 2 {
            if let Some(rest) = buf.strip_prefix("descr:") {
                let p = rest.trim_start_matches([' ', '\t']);
                if let Some(name) = p.strip_prefix("Transferred to the ") {
                    self.rir_name = Some(name.split(' ').next().unwrap_or("").to_string());
                    self.state = if self.state == 0 { 1 } else { 3 };
                }
            } else if let Some(rest) = buf.strip_prefix("mnt-by:") {
                let p = rest.trim_start_matches([' ', '\t']);
                if p == "APNIC-STUB" {
                    self.state = if self.state == 0 { 2 } else { 3 };
                }
            } else if buf.is_empty() {
                if self.state == 1 {
                    self.rir_name = None;
                }
                self.state = 0;
            }
            return;
        }
        if self.state == 3 && buf.is_empty() {
            const RIR_SERVERS: &[(&str, &str)] = &[
                ("AFRINIC", "whois.afrinic.net"),
                ("ARIN", "whois.arin.net"),
                ("LACNIC", "whois.lacnic.net"),
                ("RIPE", "whois.ripe.net"),
            ];
            self.state = 4;
            if let Some(name) = self.rir_name.take() {
                for &(rir, serv) in RIR_SERVERS {
                    if name == rir {
                        *referral = Some(serv.to_string());
                    }
                }
            }
        }
    }
}

struct ReferralTracker {
    kind: ReferralKind,
    apnic: ApnicFsm,
    state: u8,
}

impl ReferralTracker {
    fn new(kind: ReferralKind) -> Self {
        ReferralTracker { kind, apnic: ApnicFsm::new(), state: 0 }
    }

    fn feed(&mut self, line: &str, referral: &mut Option<String>) {
        match self.kind {
            ReferralKind::Apnic => self.apnic.feed(line, referral),
            ReferralKind::Arin => {
                if let Some(rest) = line.strip_prefix("ReferralServer:") {
                    // 多个 NetRange 记录时取最后一个
                    *referral = None;
                    let p = if let Some(i) = rest.find("rwhois://") {
                        Some(&rest[i + 9..])
                    } else if let Some(i) = rest.find("whois://") {
                        Some(&rest[i + 8..])
                    } else {
                        line.get(15..)
                    };
                    if let Some(p) = p {
                        let srv = p.split('/').next().unwrap_or("").trim().to_string();
                        if !srv.is_empty() {
                            *referral = Some(srv);
                        }
                    }
                }
            }
            ReferralKind::Iana => {
                if referral.is_none() {
                    if let Some(rest) = line.strip_prefix("refer:") {
                        *referral = Some(rest.trim_start_matches([' ', '\t']).to_string());
                    }
                }
            }
            ReferralKind::Recursive => {
                if self.state == 0 && line.starts_with("Domain Name:") {
                    self.state = 1;
                } else if self.state == 1 && line.starts_with("Domain Name:") {
                    self.state = 2;
                } else if self.state == 1 && line.starts_with("Registrar WHOIS Server:") {
                    *referral = Some(line[23..].trim_start_matches(' ').to_string());
                    self.state = 2;
                }
            }
            ReferralKind::Verisign => {
                if self.state == 0 && line.starts_with("   Domain Name:") {
                    self.state = 1;
                } else if self.state == 0 && line.starts_with("   Server Name:") {
                    *referral = Some(String::new());
                    self.state = 2;
                } else if self.state == 1 && line.starts_with("   Registrar WHOIS Server:") {
                    *referral = Some(line[26..].trim_start_matches(' ').to_string());
                    self.state = 2;
                }
            }
            ReferralKind::None => {}
        }
    }
}

// ---------------------------------------------------------------------------
// 网络查询

fn errno_msg(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(101) => "网络不可达".to_string(),
        Some(113) => "没有到主机的路由".to_string(),
        Some(111) => "连接被拒绝".to_string(),
        Some(110) => "连接超时".to_string(),
        Some(104) => "连接被重置".to_string(),
        _ => e.to_string(),
    }
}

fn openconn(server: &str, port: Option<&str>) -> Result<TcpStream, String> {
    let port = port.unwrap_or("43");
    let addrs: Vec<_> = match format!("{}:{}", server, port).to_socket_addrs() {
        Ok(a) => a.collect(),
        Err(e) => return Err(format!("getaddrinfo({}): {}", server, e)),
    };
    if addrs.is_empty() {
        return Err(format!("没有找到主机 {}。", server));
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut last_err = String::from("connect failed");
    for addr in addrs {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            last_err = "超时。".to_string();
            break;
        }
        match TcpStream::connect_timeout(&addr, remaining.min(Duration::from_secs(10))) {
            Ok(s) => {
                let _ = s.set_nonblocking(false);
                let _ = s.set_read_timeout(Some(Duration::from_secs(60)));
                let _ = s.set_write_timeout(Some(Duration::from_secs(60)));
                return Ok(s);
            }
            Err(e) => last_err = format!("connect: {}", errno_msg(&e)),
        }
    }
    Err(last_err)
}

/// 向服务器发送查询并读取全部响应（原样发送 query，不加变形）。
fn query_server_raw(
    server: &str,
    port: Option<&str>,
    query: &str,
    opts: &Opts,
    referral_kind: ReferralKind,
) -> Result<Response, String> {
    let mut sock = openconn(server, port)?;
    let send = format!("{}\r\n", query);
    sock.write_all(send.as_bytes()).map_err(|e| format!("write: {}", e))?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match sock.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
            Err(e) => {
                if raw.is_empty() {
                    return Err(format!("fgets: {}", errno_msg(&e)));
                }
                break; // 已收到部分数据：视为结束（部分服务器会 RST 收尾）
            }
        }
    }
    drop(sock);

    let (charset, _o) = charset_for(server, query);
    let text = crate::recode::to_utf8(&raw, charset);

    let mut hide = HideState::new(opts.hide_disclaimers);
    let mut tracker = ReferralTracker::new(referral_kind);
    let mut referral: Option<String> = None;
    let mut lines = Vec::new();

    let ends_with_nl = text.ends_with('\n');
    let mut all: Vec<&str> = text.split('\n').collect();
    if ends_with_nl {
        all.pop(); // 末尾空片段不是一行
    }
    for line in all {
        let line = line.strip_suffix('\r').unwrap_or(line);
        tracker.feed(line, &mut referral);
        if hide.hide_line(line) {
            continue;
        }
        lines.push(line.to_string());
    }

    // 避免简单的引荐死循环
    if let Some(r) = &referral {
        if r == server {
            referral = None;
        }
    }

    Ok(Response {
        server: server.to_string(),
        query: query.to_string(),
        lines,
        referral,
    })
}

// ---------------------------------------------------------------------------
// 特殊地址转换

/// strtol 语义：跳过前导空白，解析可选符号与十进制数字。
/// 无数值时返回 (0, 原始串)（C 的 endptr=nptr 行为）。
fn parse_leading_num(s: &str) -> (i64, &str) {
    let t = s.trim_start();
    let b = t.as_bytes();
    let mut i = 0;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        i += 1;
    }
    let ds = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == ds {
        return (0, s);
    }
    (t[..i].parse().unwrap_or(0), &t[i..])
}

/// sscanf %x 语义：跳过空白，允许 0x 前缀，解析十六进制数字。
fn scan_hex(s: &str) -> Option<(u32, usize)> {
    let t = s.trim_start();
    let b = t.as_bytes();
    let mut i = 0;
    if i + 1 < b.len() && b[i] == b'0' && (b[i + 1] == b'x' || b[i + 1] == b'X') {
        i += 2;
    }
    let ds = i;
    while i < b.len() && b[i].is_ascii_hexdigit() {
        i += 1;
    }
    if i == ds {
        return None;
    }
    u32::from_str_radix(&t[ds..i], 16).ok().map(|v| (v, i))
}

pub fn convert_6to4(s: &str) -> String {
    let fail = || "0.0.0.0".to_string();
    let Some(rest) = s.strip_prefix("2002:") else { return fail() };
    let Some((a, i)) = scan_hex(rest) else { return fail() };
    let rest2 = &rest[i..];
    if !rest2.starts_with(':') {
        return fail();
    }
    let rest3 = &rest2[1..];
    match scan_hex(rest3) {
        Some((b, j)) => {
            let after = &rest3[j..];
            match after.chars().next() {
                Some(':') => format!("{}.{}.{}.{}", a >> 8, a & 0xff, b >> 8, b & 0xff),
                _ => fail(),
            }
        }
        // items==1：sscanf(s, "2002:%x:%c") 要求第二个冒号存在
        None => format!("{}.{}.0.0", a >> 8, a & 0xff),
    }
}

pub fn convert_teredo(s: &str) -> String {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 8
        || parts[0] != "2001"
        || parts[1..6].iter().any(|p| p.is_empty())
    {
        return "0.0.0.0".to_string();
    }
    let a = u32::from_str_radix(parts[6], 16).unwrap_or(0) ^ 0xffff;
    let b = u32::from_str_radix(parts[7], 16).unwrap_or(0) ^ 0xffff;
    format!("{}.{}.{}.{}", a >> 8, a & 0xff, b >> 8, b & 0xff)
}

pub fn convert_inaddr(s: &str) -> String {
    let (a, rest) = parse_leading_num(s);
    let fail = || "0.0.0.0".to_string();
    if a < 0 || a > 255 || !rest.starts_with('.') {
        return fail();
    }
    let rest = &rest[1..];
    // (a, b, c) 依 C 源码的三种分支语义计算
    let (a, b, c) = if in_domain(rest, "in-addr.arpa") {
        let (b2, r2) = parse_leading_num(rest);
        if b2 < 0 || b2 > 255 || !r2.starts_with('.') {
            return fail();
        }
        let r2 = &r2[1..];
        if in_domain(r2, "in-addr.arpa") {
            let (c2, r3) = parse_leading_num(r2);
            if c2 < 0 || c2 > 255 || !r3.starts_with('.') {
                return fail();
            }
            if in_domain(&r3[1..], "in-addr.arpa") {
                return fail();
            }
            (a, b2, c2)
        } else {
            (0, a, b2)
        }
    } else {
        (0, 0, a)
    };
    format!("{}.{}.{}.0", c, b, a)
}

pub fn convert_in6arpa(s: &str) -> String {
    let Some(p) = s.find(".ip6.arpa") else {
        return String::new();
    };
    if p == 0 {
        return String::new();
    }
    let bytes = s.as_bytes();
    let mut idx = p as isize - 1; // 从 ".ip6.arpa" 前一个字符开始
    let mut ip = String::new();
    let mut digits: u32 = 1;
    loop {
        if idx < 0 {
            break;
        }
        let c = bytes[idx as usize] as char;
        if !c.is_ascii_hexdigit() {
            break;
        }
        ip.push(c.to_ascii_lowercase());
        if idx == 0 {
            break;
        }
        if ip.len() == 39 {
            break;
        }
        if digits % 4 == 0 {
            ip.push(':');
        }
        digits += 1;
        idx -= 1;
        if idx < 0 || bytes[idx as usize] != b'.' {
            break;
        }
        if idx == 0 {
            break;
        }
        idx -= 1;
    }
    ip
}

fn verisign_query_string(query: &str) -> String {
    if query.matches('.').count() == 1 && !query.contains(['=', '~', ' ']) {
        format!("domain {}", query)
    } else {
        query.to_string()
    }
}

// ---------------------------------------------------------------------------
// 查询调度（handle_query 的移植）

static QUERY_DEPTH: AtomicUsize = AtomicUsize::new(0);
const MAX_DEPTH: usize = 8;

fn run_query(
    server: &str,
    port: Option<&str>,
    query: &str,
    opts: &Opts,
    kind: ReferralKind,
) -> Result<(Response, Option<String>), String> {
    let mut resp = query_server_raw(server, port, query, opts, kind)?;
    let referral = resp.referral.take();
    Ok((resp, referral))
}

pub fn handle_query(
    hserver: &str,
    hport: Option<&str>,
    query: &str,
    flags: &str,
    opts: &Opts,
    events: &mut Vec<Event>,
) -> i32 {
    if QUERY_DEPTH.fetch_add(1, Ordering::SeqCst) >= MAX_DEPTH {
        QUERY_DEPTH.fetch_sub(1, Ordering::SeqCst);
        return 1;
    }

    let mut server: String;
    let port: Option<String>;
    if let Some(p) = hport {
        server = hserver.to_string();
        port = Some(p.to_string());
    } else if hserver.chars().next().is_some_and(|c| (c as u32) < 0x20) {
        server = hserver.to_string();
        port = None;
    } else {
        let (s, p) = split_server_port(hserver);
        server = s;
        port = p;
    }

    let mut query = query.to_string();
    let ret: i32;

    'retry: loop {
        let first = server.chars().next().unwrap_or('\0') as u32;
        match first {
            0 => {
                server = std::env::var("WHOIS_SERVER")
                    .unwrap_or_else(|_| DEFAULT_SERVER.to_string());
            }
            1 => {
                events.push(Event::Message(
                    "此顶级域名没有 whois 服务器，但您可在这里访问 whois 数据库：".to_string(),
                ));
                events.push(Event::Message(server[1..].to_string()));
                ret = 1;
                break 'retry;
            }
            3 => {
                events.push(Event::Message("此顶级域名没有对应的 whois 服务器。".to_string()));
                ret = 1;
                break 'retry;
            }
            5 => {
                events.push(Event::Message("无针对此类对象的 whois 服务器。".to_string()));
                ret = 1;
                break 'retry;
            }
            6 => {
                events.push(Event::Message("未知的 AS 号码或 IP 地址。请升级此程序。".to_string()));
                ret = 1;
                break 'retry;
            }
            4 => {
                let real = server[1..].to_string();
                if opts.verbose {
                    events.push(Event::Verbose(format!("使用服务器 {}。", real)));
                }
                let q = verisign_query_string(&query);
                match run_query(&real, None, &q, opts, ReferralKind::Verisign) {
                    Ok((resp, referral)) => {
                        events.push(Event::Response(resp));
                        server = referral.unwrap_or_default();
                        if opts.no_recursion && !server.is_empty() {
                            server = String::new();
                        }
                    }
                    Err(e) => {
                        events.push(Event::Error(e));
                        ret = 1;
                        break 'retry;
                    }
                }
            }
            8 => {
                let real = server[1..].to_string();
                if opts.verbose {
                    events.push(Event::Verbose(format!("使用服务器 {}。", real)));
                }
                match run_query(&real, None, &query, opts, ReferralKind::Recursive) {
                    Ok((resp, referral)) => {
                        events.push(Event::Response(resp));
                        server = referral.unwrap_or_default();
                        if opts.no_recursion && !server.is_empty() {
                            server = String::new();
                        }
                    }
                    Err(e) => {
                        events.push(Event::Error(e));
                        ret = 1;
                        break 'retry;
                    }
                }
            }
            0x0A => {
                let p = convert_6to4(&query);
                events.push(Event::Notice(format!(
                    "\n查询和一个6to4 IPv6 地址相对应的 IPv4 终端 {}。\n\n",
                    p
                )));
                server = guess_server(&p);
                query = p;
                continue 'retry;
            }
            0x0B => {
                let p = convert_teredo(&query);
                events.push(Event::Notice(format!(
                    "\n查询一个Teredo IPv6 地址相对应的 IPv4 终端 {}。\n\n",
                    p
                )));
                server = guess_server(&p);
                query = p;
                continue 'retry;
            }
            0x0C => {
                let p = convert_inaddr(&query);
                server = guess_server(&p);
                query = p;
                continue 'retry;
            }
            0x0D => {
                let p = convert_in6arpa(&query);
                server = guess_server(&p);
                query = p;
                continue 'retry;
            }
            0x0E => {
                if opts.verbose {
                    events.push(Event::Verbose("使用服务器 whois.iana.org。".to_string()));
                }
                match run_query("whois.iana.org", None, &query, opts, ReferralKind::Iana) {
                    Ok((resp, referral)) => {
                        events.push(Event::Response(resp));
                        server = referral.unwrap_or_default();
                    }
                    Err(e) => {
                        events.push(Event::Error(e));
                        ret = 1;
                        break 'retry;
                    }
                }
            }
            _ => {}
        }

        if server.is_empty() {
            ret = 0;
            break 'retry;
        }

        let qs = queryformat(&server, flags, &query, &opts.client_tag);
        if opts.verbose {
            events.push(Event::Verbose(format!("使用服务器 {}。", server)));
            events.push(Event::Verbose(format!("查询字符串: \"{}\"", qs)));
            events.push(Event::Verbose(String::new()));
        }

        match run_query(&server, port.as_deref(), &qs, opts, referral_kind_for(&server)) {
            Ok((resp, new_server)) => {
                events.push(Event::Response(resp));
                // 递归很有趣
                if !opts.no_recursion && new_server.is_some() && !query.contains(' ') {
                    let ns = new_server.unwrap();
                    events.push(Event::ReferralBanner(ns.clone()));
                    ret = handle_query(&ns, None, &query, flags, opts, events);
                } else {
                    ret = 0;
                }
            }
            Err(e) => {
                events.push(Event::Error(e));
                ret = 1;
            }
        }
        break 'retry;
    }

    QUERY_DEPTH.fetch_sub(1, Ordering::SeqCst);
    ret
}
