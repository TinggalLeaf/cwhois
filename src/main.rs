// cwhois —— 中文 whois 客户端：完整兼容 whois 命令行参数与全部输出，
// 默认提供彩色美化渲染（TTY），管道/脚本场景输出与 whois 一致的原始文本。

mod color;
mod data;
mod parse;
mod punycode;
mod recode;
mod render;
mod server;

use color::ColorMode;
use server::{Event, Opts};
use std::io::IsTerminal;
use std::time::Instant;

const VERSION: &str = "0.1.0";

// ---------------------------------------------------------------------------
// getopt_long 兼容的参数解析

const RIPEFLAGS: &str = "abBcdFGKlLmMrRx";
const RIPEFLAGSP: &str = "gisTtvq";

#[derive(Clone, Copy, PartialEq)]
enum ArgKind {
    NoArg,
    Required,
}

struct LongOpt {
    name: &'static str,
    kind: ArgKind,
    /// 短选项字符、或 1=version 2=verbose 3=help 4=no-recursion
    /// 10/11/12 = 追加 --name 形式的 RIPE 长标志
    id: u32,
}

const LONGOPTS: &[LongOpt] = &[
    LongOpt { name: "version", kind: ArgKind::NoArg, id: 1 },
    LongOpt { name: "verbose", kind: ArgKind::NoArg, id: 2 },
    LongOpt { name: "help", kind: ArgKind::NoArg, id: 3 },
    LongOpt { name: "no-recursion", kind: ArgKind::NoArg, id: 4 },
    LongOpt { name: "server", kind: ArgKind::Required, id: 'h' as u32 },
    LongOpt { name: "host", kind: ArgKind::Required, id: 'h' as u32 },
    LongOpt { name: "port", kind: ArgKind::Required, id: 'p' as u32 },
    // 以下长选项与上游 whois 一致：声明为带参数，但实际当作无参数 RIPE 标志处理
    LongOpt { name: "exact", kind: ArgKind::Required, id: 'x' as u32 },
    LongOpt { name: "all-more", kind: ArgKind::Required, id: 'M' as u32 },
    LongOpt { name: "one-more", kind: ArgKind::Required, id: 'm' as u32 },
    LongOpt { name: "all-less", kind: ArgKind::Required, id: 'L' as u32 },
    LongOpt { name: "one-less", kind: ArgKind::Required, id: 'l' as u32 },
    LongOpt { name: "reverse-domain", kind: ArgKind::Required, id: 'd' as u32 },
    LongOpt { name: "irt", kind: ArgKind::Required, id: 'c' as u32 },
    LongOpt { name: "abuse-contact", kind: ArgKind::NoArg, id: 'b' as u32 },
    LongOpt { name: "brief", kind: ArgKind::NoArg, id: 'F' as u32 },
    LongOpt { name: "primary-keys", kind: ArgKind::NoArg, id: 'K' as u32 },
    LongOpt { name: "persistent-connection", kind: ArgKind::NoArg, id: 'k' as u32 },
    LongOpt { name: "no-referenced", kind: ArgKind::NoArg, id: 'r' as u32 },
    LongOpt { name: "no-filtering", kind: ArgKind::NoArg, id: 'B' as u32 },
    LongOpt { name: "no-grouping", kind: ArgKind::NoArg, id: 'G' as u32 },
    LongOpt { name: "select-types", kind: ArgKind::Required, id: 'T' as u32 },
    LongOpt { name: "all-sources", kind: ArgKind::NoArg, id: 'a' as u32 },
    LongOpt { name: "sources", kind: ArgKind::Required, id: 's' as u32 },
    LongOpt { name: "types", kind: ArgKind::NoArg, id: 12 },
    LongOpt { name: "ripe-version", kind: ArgKind::NoArg, id: 12 },
    LongOpt { name: "list-sources", kind: ArgKind::NoArg, id: 12 },
    LongOpt { name: "template", kind: ArgKind::Required, id: 't' as u32 },
    LongOpt { name: "ripe-verbose", kind: ArgKind::Required, id: 'v' as u32 },
    LongOpt { name: "list-versions", kind: ArgKind::NoArg, id: 10 },
    LongOpt { name: "diff-versions", kind: ArgKind::Required, id: 11 },
    LongOpt { name: "show-version", kind: ArgKind::Required, id: 11 },
    LongOpt { name: "resource", kind: ArgKind::NoArg, id: 10 },
    LongOpt { name: "show-personal", kind: ArgKind::NoArg, id: 10 },
    LongOpt { name: "no-personal", kind: ArgKind::NoArg, id: 10 },
    LongOpt { name: "show-tag-info", kind: ArgKind::NoArg, id: 10 },
    LongOpt { name: "no-tag-info", kind: ArgKind::NoArg, id: 10 },
    LongOpt { name: "filter-tag-include", kind: ArgKind::Required, id: 11 },
    LongOpt { name: "filter-tag-exclude", kind: ArgKind::Required, id: 11 },
    // cwhois 扩展
    LongOpt { name: "raw", kind: ArgKind::NoArg, id: 1000 },
    LongOpt { name: "pretty", kind: ArgKind::NoArg, id: 1001 },
    LongOpt { name: "color", kind: ArgKind::Required, id: 1002 },
];

/// 短选项 → 是否带参数
fn short_takes_arg(c: char) -> bool {
    matches!(c, 'g' | 'h' | 'i' | 'p' | 'q' | 's' | 't' | 'T' | 'v' | 'V')
}

struct ParsedArgs {
    server: Option<String>,
    port: Option<String>,
    hide: bool,
    iana: bool,
    verbose: bool,
    no_recursion: bool,
    client_tag: String,
    fstring: String,
    nopar: bool,
    raw: bool,
    pretty: bool,
    color: Option<ColorMode>,
    operands: Vec<String>,
}

fn parse_args(argv: &[String]) -> Result<ParsedArgs, i32> {
    let mut a = ParsedArgs {
        server: None,
        port: None,
        hide: false,
        iana: false,
        verbose: false,
        no_recursion: false,
        client_tag: server::CLIENT_TAG.to_string(),
        fstring: String::new(),
        nopar: false,
        raw: false,
        pretty: false,
        color: None,
        operands: Vec::new(),
    };

    let mut i = 0;
    let mut only_operands = false;
    while i < argv.len() {
        let arg = &argv[i];
        if only_operands || !arg.starts_with('-') || arg == "-" {
            a.operands.push(arg.clone());
            i += 1;
            continue;
        }
        if arg == "--" {
            only_operands = true;
            i += 1;
            continue;
        }

        if let Some(long) = arg.strip_prefix("--") {
            // 长选项
            let (name, inline_val) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (long, None),
            };
            // 唯一前缀匹配
            let matches: Vec<&LongOpt> = LONGOPTS
                .iter()
                .filter(|o| o.name.starts_with(name))
                .collect();
            let opt = if matches.len() == 1 {
                matches[0]
            } else if matches.iter().any(|o| o.name == name) {
                matches.iter().find(|o| o.name == name).unwrap()
            } else {
                eprintln!("cwhois: unrecognized option '--{}'", name);
                usage(1);
            };
            let mut val = inline_val;
            if opt.kind == ArgKind::Required && val.is_none() {
                i += 1;
                if i < argv.len() {
                    val = Some(argv[i].clone());
                } else {
                    eprintln!("cwhois: option '--{}' requires an argument", opt.name);
                    usage(1);
                }
            }
            handle_opt(&mut a, opt.id, opt.name, val)?;
            i += 1;
            continue;
        }

        // 短选项（可捆绑，带参选项吃掉剩余部分或下一个参数）
        let chars: Vec<char> = arg[1..].chars().collect();
        let mut j = 0;
        while j < chars.len() {
            let c = chars[j];
            if short_takes_arg(c) {
                let inline: String = chars[j + 1..].iter().collect();
                let val = if !inline.is_empty() {
                    Some(inline)
                } else {
                    i += 1;
                    if i < argv.len() {
                        Some(argv[i].clone())
                    } else {
                        eprintln!("cwhois: option requires an argument -- '{}'", c);
                        usage(1);
                    }
                };
                handle_opt(&mut a, c as u32, "", val)?;
                break;
            } else {
                handle_opt(&mut a, c as u32, "", None)?;
                j += 1;
            }
        }
        i += 1;
    }
    Ok(a)
}

fn handle_opt(a: &mut ParsedArgs, id: u32, name: &str, val: Option<String>) -> Result<(), i32> {
    let ch = char::from_u32(id);
    // RIPE 无参标志
    if let Some(c) = ch {
        if RIPEFLAGS.contains(c) {
            a.fstring.push('-');
            a.fstring.push(c);
            a.fstring.push(' ');
            return Ok(());
        }
        if RIPEFLAGSP.contains(c) {
            let v = val.unwrap_or_default();
            a.fstring.push('-');
            a.fstring.push(c);
            a.fstring.push(' ');
            a.fstring.push_str(&v);
            a.fstring.push(' ');
            if c == 't' || c == 'v' || c == 'q' {
                a.nopar = true;
            }
            return Ok(());
        }
    }
    match id {
        1 => {
            println!("cwhois 版本 {}。", VERSION);
            println!();
            println!("报告错误: <https://github.com/>");
            std::process::exit(0);
        }
        2 => a.verbose = true,
        3 => usage(0),
        4 => a.no_recursion = true,
        1000 => a.raw = true,
        1001 => a.pretty = true,
        1002 => {
            a.color = Some(match val.as_deref().unwrap_or("auto") {
                "always" => ColorMode::Always,
                "never" => ColorMode::Never,
                _ => ColorMode::Auto,
            });
        }
        10 => {
            a.fstring.push_str("--");
            a.fstring.push_str(name);
            a.fstring.push(' ');
        }
        11 => {
            a.fstring.push_str("--");
            a.fstring.push_str(name);
            a.fstring.push(' ');
            a.fstring.push_str(&val.unwrap_or_default());
            a.fstring.push(' ');
        }
        12 => {
            a.nopar = true;
            a.fstring.push_str("--");
            a.fstring.push_str(name);
            a.fstring.push(' ');
        }
        _ => match ch {
            Some('h') => a.server = val,
            Some('V') => a.client_tag = val.unwrap(),
            Some('H') => a.hide = true,
            Some('I') => a.iana = true,
            Some('p') => a.port = val,
            _ => {
                eprintln!("cwhois: invalid option -- '{}'", ch.unwrap_or('?'));
                usage(1);
            }
        },
    }
    Ok(())
}

fn usage(exit_code: i32) -> ! {
    use std::io::Write;
    let text = concat!(
        "用法: cwhois [选项]... 对象...\n",
        "\n",
        "  -h HOST, --host HOST   连接到服务器 HOST\n",
        "  -p PORT, --port PORT   连接到端口 PORT\n",
        "  -I                     查询 whois.iana.org 并跟踪其引荐\n",
        "  -H                     隐藏法律免责声明\n",
        "      --verbose          显示执行过程\n",
        "      --no-recursion     禁用从注册局到注册商服务器的递归\n",
        "      --help             显示本帮助并退出\n",
        "      --version          输出版本信息并退出\n",
        "\n",
        "以下标志受 whois.ripe.net 及若干 RIPE 风格服务器支持:\n",
        "-l                     查找第一个不那么具体的匹配\n",
        "-L                     查找所有不那么具体的匹配\n",
        "-m                     查找所有恰好更具体一级的匹配\n",
        "-M                     查找所有更具体的匹配\n",
        "-c                     查找包含 mnt-irt 属性的最小匹配\n",
        "-x                     精确匹配\n",
        "-b                     返回附滥用联系方式的简要 IP 地址段\n",
        "-B                     关闭对象过滤（显示电子邮箱地址）\n",
        "-G                     关闭关联对象分组\n",
        "-d                     同时返回 DNS 反向委托对象\n",
        "-i ATTR[,ATTR]...      按指定 ATTRibute 做反向查询\n",
        "-T TYPE[,TYPE]...      只查找指定 TYPE 的对象\n",
        "-K                     只返回主键及其值\n",
        "-r                     关闭联系信息的递归查询\n",
        "-R                     强制显示含有引荐的域名对象的本地副本\n",
        "-a                     同时搜索所有镜像数据库\n",
        "-s SOURCE[,SOURCE]...  搜索镜像自 SOURCE 的数据库\n",
        "-g SOURCE:FIRST-LAST   查找 SOURCE 中从序列号 FIRST 到 LAST 的更新\n",
        "-t TYPE                请求 TYPE 类型对象的模板\n",
        "-v TYPE                请求 TYPE 类型对象的详细模板\n",
        "-q [version|sources|types]  查询指定服务器信息\n",
        "\n",
        "cwhois 扩展选项:\n",
        "      --raw              输出与 whois 一致的原始文本\n",
        "      --pretty           强制彩色美化输出（即使输出被重定向）\n",
        "      --color=WHEN       颜色模式: auto(默认) / always / never\n",
    );
    if exit_code == 0 {
        let mut out = std::io::stdout();
        let _ = out.write_all(text.as_bytes());
        let _ = out.flush();
    } else {
        let mut out = std::io::stderr();
        let _ = out.write_all(text.as_bytes());
        let _ = out.flush();
    }
    std::process::exit(exit_code)
}

// ---------------------------------------------------------------------------
// /etc/whois.conf 匹配（ERE 子集：^ $ . \. * [] 字面量）

#[derive(Clone)]
enum RegexItem {
    Char(char),
    Any,
    Class(Vec<(char, char)>, bool), // 范围列表，是否取反
    Group(Vec<Vec<RegexItem>>),     // (a|b) —— 简化支持
}
struct RegexParser<'a> {
    chars: Vec<char>,
    pos: usize,
    _m: std::marker::PhantomData<&'a ()>,
}

impl<'a> RegexParser<'a> {
    fn new(pattern: &str) -> Self {
        RegexParser { chars: pattern.chars().collect(), pos: 0, _m: std::marker::PhantomData }
    }
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }
    fn next(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }
    fn parse_alt(&mut self) -> Vec<Vec<RegexItem>> {
        let mut alts = Vec::new();
        let mut cur = Vec::new();
        while let Some(c) = self.peek() {
            match c {
                ')' => break,
                '|' => {
                    self.next();
                    alts.push(std::mem::take(&mut cur));
                }
                '(' => {
                    self.next();
                    let g = self.parse_alt();
                    if self.peek() == Some(')') {
                        self.next();
                    }
                    cur.push(RegexItem::Group(g));
                }
                '[' => {
                    self.next();
                    let (ranges, neg) = self.parse_class();
                    cur.push(RegexItem::Class(ranges, neg));
                }
                '.' => {
                    self.next();
                    cur.push(RegexItem::Any);
                }
                '\\' => {
                    self.next();
                    if let Some(c2) = self.next() {
                        cur.push(RegexItem::Char(c2));
                    }
                }
                '*' => {
                    self.next();
                    // 对最后一项应用星号：转换为 Group 重复 0..=4 次（够用）
                    if let Some(last) = cur.pop() {
                        cur.push(RegexItem::Group(vec![
                            vec![],
                            vec![last.clone()],
                            vec![last.clone(), last.clone()],
                            vec![last.clone(), last.clone(), last.clone()],
                        ]));
                    }
                }
                '+' => {
                    self.next();
                    if let Some(last) = cur.pop() {
                        cur.push(RegexItem::Group(vec![
                            vec![last.clone()],
                            vec![last.clone(), last.clone()],
                            vec![last.clone(), last.clone(), last.clone()],
                        ]));
                    }
                }
                '?' => {
                    self.next();
                    if let Some(last) = cur.pop() {
                        cur.push(RegexItem::Group(vec![vec![], vec![last]]));
                    }
                }
                '^' if cur.is_empty() && self.pos == 1 => {
                    self.next(); // 行首锚点在匹配器中处理
                }
                '$' => {
                    self.next();
                    alts.push(std::mem::take(&mut cur));
                    break;
                }
                _ => {
                    self.next();
                    cur.push(RegexItem::Char(c));
                }
            }
        }
        alts.push(cur);
        alts
    }
    fn parse_class(&mut self) -> (Vec<(char, char)>, bool) {
        let mut neg = false;
        if self.peek() == Some('^') {
            neg = true;
            self.next();
        }
        let mut ranges = Vec::new();
        let mut prev: Option<char> = None;
        while let Some(c) = self.peek() {
            if c == ']' {
                self.next();
                break;
            }
            self.next();
            if c == '-' {
                if let (Some(s), Some(e)) = (prev.take(), self.peek()) {
                    if e != ']' {
                        self.next();
                        ranges.push((s, e));
                        continue;
                    }
                }
                ranges.push(('-', '-'));
            } else {
                if let Some(p) = prev.take() {
                    ranges.push((p, p));
                }
                prev = Some(c);
            }
        }
        if let Some(p) = prev {
            ranges.push((p, p));
        }
        (ranges, neg)
    }
}

fn match_alt(alts: &[Vec<RegexItem>], s: &[char]) -> bool {
    alts.iter().any(|alt| match_seq(alt, s))
}

fn match_seq(seq: &[RegexItem], s: &[char]) -> bool {
    if seq.is_empty() {
        return s.is_empty();
    }
    match &seq[0] {
        RegexItem::Char(c) => !s.is_empty() && s[0] == *c && match_seq(&seq[1..], &s[1..]),
        RegexItem::Any => !s.is_empty() && s[0] != '\n' && match_seq(&seq[1..], &s[1..]),
        RegexItem::Class(ranges, neg) => {
            if s.is_empty() {
                return false;
            }
            let mut m = ranges.iter().any(|(a, b)| s[0] >= *a && s[0] <= *b);
            if *neg {
                m = !m;
            }
            m && match_seq(&seq[1..], &s[1..])
        }
        RegexItem::Group(alts) => {
            for alt in alts {
                // 尝试该分支的所有可能消耗长度
                for k in 0..=s.len() {
                    if match_seq(alt, &s[..k]) && match_seq(&seq[1..], &s[k..]) {
                        return true;
                    }
                }
            }
            false
        }
    }
}

fn match_config_file(s: &str) -> Option<String> {
    let path = "/etc/whois.conf";
    let Ok(content) = std::fs::read_to_string(path) else {
        return None;
    };
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        let (Some(pattern), Some(server)) = (it.next(), it.next()) else {
            continue;
        };
        // ERE 子集 → 匹配器
        let anchored_start = pattern.starts_with('^');
        let anchored_end = pattern.ends_with('$') && !pattern.ends_with("\\$");
        let pat = pattern.trim_start_matches('^').trim_end_matches('$');
        let mut parser = RegexParser::new(pat);
        let alts = parser.parse_alt();
        let chars: Vec<char> = s.to_lowercase().chars().collect();
        let pat_chars_len = chars.len();
        let _ = pat_chars_len;
        let ok = if anchored_start && anchored_end {
            match_alt(&alts, &chars)
        } else if anchored_end {
            // 后缀匹配：从每个位置尝试到结尾
            (0..=chars.len()).rev().any(|i| match_alt(&alts, &chars[i..]))
        } else if anchored_start {
            (0..=chars.len()).any(|k| match_alt(&alts, &chars[..k]))
        } else {
            (0..chars.len()).any(|i| (1..=chars.len() - i).any(|k| match_alt(&alts, &chars[i..i + k])))
        };
        if ok {
            return Some(server.to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// 主流程

fn main() {
    let mut argv: Vec<String> = std::env::args().skip(1).collect();
    // 环境变量中的选项排在最前（与 whois 一致）
    if let Ok(opts) = std::env::var("WHOIS_OPTIONS") {
        let env_args: Vec<String> = opts.split_whitespace().map(String::from).collect();
        let mut merged = env_args;
        merged.append(&mut argv);
        argv = merged;
    }

    let mut args = match parse_args(&argv) {
        Ok(a) => a,
        Err(code) => std::process::exit(code),
    };

    if args.operands.is_empty() && !args.nopar {
        usage(1);
    }

    let qstring = args.operands.join(" ");
    let fstring = args.fstring.clone();

    if std::env::var_os("WHOIS_HIDE").is_some() {
        args.hide = true;
    }

    let opts = Opts {
        verbose: args.verbose,
        no_recursion: args.no_recursion,
        hide_disclaimers: args.hide,
        client_tag: args.client_tag,
    };

    // 服务器选择
    let mut server: Option<String> = args.server.clone();
    if args.iana {
        server = Some("\u{e}".to_string());
    }
    if server.is_none() && (qstring.is_empty() || !fstring.is_empty()) {
        server = Some("whois.ripe.net".to_string());
    }
    let qstring = if qstring.is_empty() {
        qstring
    } else {
        server::normalize_domain(&qstring)
    };
    if server.is_none() {
        server = match_config_file(&qstring);
    }
    if server.is_none() {
        server = Some(server::guess_server(&qstring));
    }

    // 输出模式：TTY 默认美化；管道默认原始（可被 --pretty 覆盖）；--raw/-F 强制原始
    let stdout_tty = std::io::stdout().is_terminal();
    let f_has_fast = fstring.split_whitespace().any(|t| t == "-F");
    let mut raw_mode = args.raw || f_has_fast;
    if !stdout_tty && !args.pretty {
        raw_mode = true;
    }

    color::init_color(args.color.unwrap_or(ColorMode::Auto), stdout_tty);

    let start = Instant::now();
    let mut events: Vec<Event> = Vec::new();
    let ret = server::handle_query(
        server.as_deref().unwrap_or(""),
        args.port.as_deref(),
        &qstring,
        &fstring,
        &opts,
        &mut events,
    );
    let elapsed = start.elapsed();

    let mut out = String::new();
    let mut err_out = String::new();
    if raw_mode {
        render::render_raw(&events, &mut out, &mut err_out);
    } else {
        let po = render::PrettyOpts {
            width: color::term_width(),
            query: if qstring.is_empty() { fstring.clone() } else { qstring.clone() },
            elapsed,
            show_hint: stdout_tty,
        };
        render::render_pretty(&events, &po, &mut out, &mut err_out);
    }
    use std::io::Write;
    // 复刻 whois 的缓冲行为：重定向时 stderr 先于 stdout 落盘，终端上相反
    if stdout_tty {
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        let _ = lock.write_all(out.as_bytes());
        let _ = lock.flush();
        if !err_out.is_empty() {
            let stderr = std::io::stderr();
            let mut elock = stderr.lock();
            let _ = elock.write_all(err_out.as_bytes());
            let _ = elock.flush();
        }
    } else {
        if !err_out.is_empty() {
            let stderr = std::io::stderr();
            let mut elock = stderr.lock();
            let _ = elock.write_all(err_out.as_bytes());
            let _ = elock.flush();
        }
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        let _ = lock.write_all(out.as_bytes());
        let _ = lock.flush();
    }

    std::process::exit(ret);
}
