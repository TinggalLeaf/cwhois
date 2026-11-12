// 渲染层：原始输出（与 whois 逐字节一致）与中文彩色美化输出。

use crate::color::*;
use crate::parse::{self, Line, Object, Parsed};
use crate::server::Event;
use std::fmt::Write as _;

// ---------------------------------------------------------------------------
// 中文标签词典：whois 键名 → 中文

pub fn zh_label(key: &str) -> Option<&'static str> {
    Some(match key {
        // ---- gTLD / 注册局（thin/thick registry）----
        "domain name" | "domain" | "domain-handle" | "domain name handle" => "域名",
        "roid" => "注册局对象 ID",
        "registry domain id" => "注册局域名 ID",
        "registrar whois server" => "注册商 WHOIS 服务器",
        "registrar url" | "url" | "registrar url(registrar):" | "referral url" => "注册商网址",
        "updated date" | "updated" | "last updated" | "last update" | "changed" | "modify" | "modified" => "更新日期",
        "creation date" | "registration date" | "registration time" | "registered on" => "创建日期",
        "registry expiry date" | "registrar registration expiration date" | "expiry date"
        | "expiration date" | "expire" | "expire date" | "expires" | "paid-till" | "renewal date"
        | "expiration time" | "registry expiry" => "到期日期",
        "registrar" | "registrar name" => "注册商",
        "registrar iana id" => "注册商 IANA ID",
        "registrar abuse contact email" => "注册商滥用举报邮箱",
        "registrar abuse contact phone" => "注册商滥用举报电话",
        "reseller" => "分销商",
        "domain status" | "status" | "domainstatus" | "state" | "eligstatus" => "状态",
        "dnssec" | "dnssec status" | "dnssec signing" => "DNSSEC",
        "dnssec ds data" | "dnssec delegation signer data" => "DNSSEC DS 记录",
        "dnssec delegation signer" | "ds" | "ds-rdata" => "DS 记录",
        "dnskey" => "DNSKEY",
        "name server" | "nserver" | "nameserver" | "name servers" | "name server handle" => "域名服务器",
        "whois server" => "WHOIS 服务器",
        ">>> last update of whois database" => "WHOIS 数据库最后更新",
        "url of the icann whois inaccuracy complaint form" | "whois inaccuracy complaint form" => "ICANN WHOIS 投诉表单",
        "url of the icann whois inaccuracy complaint" => "ICANN WHOIS 投诉地址",

        // ---- 联系人（注册人/管理/技术/财务）----
        "registrant" => "注册人",
        "registrant id" | "registrant handle" => "注册人 ID",
        "registrant name" => "注册人姓名",
        "registrant organization" | "registrant organisation" => "注册人组织",
        "registrant street" => "注册人地址",
        "registrant city" => "注册人城市",
        "registrant state/province" | "registrant state" => "注册人省/州",
        "registrant postal code" => "注册人邮编",
        "registrant country" => "注册人国家/地区",
        "registrant phone" => "注册人电话",
        "registrant phone ext" => "注册人电话分机",
        "registrant fax" => "注册人传真",
        "registrant email" | "registrant e-mail" | "registrant mailbox" => "注册人邮箱",
        "admin" | "admin contact" | "administrative contact" => "管理联系人",
        "admin id" | "admin handle" | "admin-c" | "admin-contact" => "管理联系人 ID",
        "admin name" => "管理联系人姓名",
        "admin organization" | "admin organisation" => "管理联系人组织",
        "admin street" => "管理联系人地址",
        "admin city" => "管理联系人城市",
        "admin state/province" => "管理联系人省/州",
        "admin postal code" => "管理联系人邮编",
        "admin country" => "管理联系人国家/地区",
        "admin phone" => "管理联系人电话",
        "admin phone ext" => "管理联系人电话分机",
        "admin fax" => "管理联系人传真",
        "admin email" | "admin e-mail" => "管理联系人邮箱",
        "tech" | "tech contact" | "technical contact" => "技术联系人",
        "tech id" | "tech handle" | "tech-c" | "tech-contact" => "技术联系人 ID",
        "tech name" => "技术联系人姓名",
        "tech organization" | "tech organisation" => "技术联系人组织",
        "tech street" => "技术联系人地址",
        "tech city" => "技术联系人城市",
        "tech state/province" => "技术联系人省/州",
        "tech postal code" => "技术联系人邮编",
        "tech country" => "技术联系人国家/地区",
        "tech phone" => "技术联系人电话",
        "tech phone ext" => "技术联系人电话分机",
        "tech fax" => "技术联系人传真",
        "tech email" | "tech e-mail" => "技术联系人邮箱",
        "billing" | "billing contact" => "财务联系人",
        "billing id" | "billing handle" => "财务联系人 ID",
        "billing name" => "财务联系人姓名",
        "billing organization" | "billing organisation" => "财务联系人组织",
        "billing email" | "billing e-mail" => "财务联系人邮箱",

        // ---- ARIN ----
        "netrange" => "IP 范围",
        "cidr" => "CIDR",
        "netname" | "network name" => "网络名称",
        "nethandle" => "网络句柄",
        "parent" => "上级网络",
        "nettype" => "网络类型",
        "originas" => "起源 ASN",
        "organization" | "orgname" | "org-name" | "organisation" => "组织名称",
        "orgid" | "org id" => "组织 ID",
        "orgtype" | "org-type" => "组织类型",
        "orgtechname" => "组织技术联系人",
        "orgtechphone" => "组织技术联系人电话",
        "orgtechemail" => "组织技术联系人邮箱",
        "orgtechhandle" => "组织技术联系人句柄",
        "orgtechref" => "组织技术联系人参考",
        "orgabusehandle" => "组织滥用举报联系人",
        "orgabusephone" => "组织滥用举报电话",
        "orgabuseemail" => "组织滥用举报邮箱",
        "orgabuseref" => "组织滥用举报参考",
        "orgnocshandle" => "组织运维联系人句柄",
        "rtechname" => "技术联系人",
        "rtechphone" => "技术联系人电话",
        "rtechemail" => "技术联系人邮箱",
        "rtechhandle" => "技术联系人句柄",
        "rtechref" => "技术联系人参考",
        "rnocshandle" => "运维联系人句柄",
        "rnocsname" => "运维联系人",
        "rnocsphone" => "运维联系人电话",
        "rnocsemail" => "运维联系人邮箱",
        "rabusehandle" => "滥用举报联系人",
        "rabusename" => "滥用举报联系人姓名",
        "rabusephone" => "滥用举报电话",
        "rabuseemail" => "滥用举报邮箱",
        "rabuseref" => "滥用举报参考",
        "custhandle" => "客户句柄",
        "custname" => "客户名称",
        "custstreet" => "客户地址",
        "custcity" => "客户城市",
        "custstateprov" => "客户省/州",
        "custpostalcode" => "客户邮编",
        "custcountry" => "客户国家/地区",
        "custphone" => "客户电话",

        // ---- RIPE / RPSL ----
        "inetnum" => "IP 范围",
        "inet6num" => "IPv6 范围",
        "descr" | "description" => "描述",
        "country" => "国家/地区",
        "geoloc" => "地理位置",
        "language" => "语言",
        "abuse-c" => "滥用举报联系人",
        "abuse-mailbox" => "滥用举报邮箱",
        "mnt-by" => "维护者",
        "mnt-lower" => "下级维护者",
        "mnt-routes" => "路由维护者",
        "mnt-domains" => "域名维护者",
        "mnt-irt" => "IRT 引用",
        "mntner" => "维护者",
        "mnt-nfy" => "维护通知邮箱",
        "mnt-ref" => "维护者引用",
        "auth" => "认证方式",
        "person" | "contact name" | "owner" => "姓名",
        "role" | "trouble" => "角色",
        "e-mail" | "email" | "mailbox" | "e-mail address" => "电子邮箱",
        "phone" | "phone number" | "voice" => "电话",
        "fax-no" | "fax" => "传真",
        "nic-hdl" | "nic handle" | "handle" => "NIC 句柄",
        "remarks" | "remark" => "备注",
        "comment" => "备注",
        "notify" => "通知邮箱",
        "referto" | "refer" => "引荐",
        "route" => "路由",
        "route6" => "IPv6 路由",
        "origin" => "起源 AS",
        "aut-num" => "自治系统号",
        "as-name" => "AS 名称",
        "as-set" => "AS 集合",
        "as-block" => "AS 区块",
        "members" => "成员",
        "mbrs-by-ref" => "成员引用",
        "mp-members" => "多协议成员",
        "org" => "组织",
        "irt" => "IRT（事件响应团队）",
        "irt-nfy" => "IRT 通知邮箱",
        "authentication" => "认证方式",
        "pingable" => "可 Ping",
        "ping-hdl" => "Ping 联系人",
        "created" => "创建时间",
        "last-modified" => "最后修改",
        "source" => "数据来源",
        "zone-c" => "区域联系人",
        "gateway" => "网关",
        "author" => "作者",
        "delegation" => "委托",
        "reverse delegation" => "反向委托",
        "robots?" => "描述",

        // ---- ccTLD 杂项 ----
        "registrant contact" => "注册人",
        "registrant contact email" => "注册人邮箱",
        "registrant contact voice" => "注册人电话",
        "registrant contact fax" => "注册人传真",
        "registrar organization" => "注册商组织",
        "sponsoring registrar organization" => "赞助注册商组织",
        "sponsoring registrar iana id" => "赞助注册商 IANA ID",
        "sponsoring registrar url" => "赞助注册商网址",
        "sponsoring registrar creation date" => "赞助注册商创建日期",
        "sponsoring registrar phone" => "赞助注册商电话",
        "sponsoring registrar email" => "赞助注册商邮箱",
        "domain expiration date" => "域名到期日期",
        "registrar email" => "注册商邮箱",
        "registrar phone" => "注册商电话",
        "dns servers" => "DNS 服务器",
        "dns server" => "DNS 服务器",
        "primary server" => "主 DNS 服务器",
        "secondary server" => "辅 DNS 服务器",
        "holder" => "持有者",
        "holder-c" => "持有者句柄",
        "holder email" => "持有者邮箱",
        "holder phone" => "持有者电话",
        "holder address" => "持有者地址",
        "holder postal code" => "持有者邮编",
        "holder city" => "持有者城市",
        "nserver handle" => "域名服务器句柄",
        "dnssec key" => "DNSSEC 密钥",
        "free-date" => "释放日期",
        "deletion date" => "删除日期",
        "registered date" => "注册日期",
        "last modified" | "last modified date" => "最后修改",
        "last update of whois database" => "WHOIS 数据库最后更新",
        "notice" => "声明",
        "terms of use" => "使用条款",
        ">>> last update" => "WHOIS 数据库最后更新",
        "sponsoring registrar" => "赞助注册商",

        // ---- 通用 ----
        "address" | "street" | "street address" => "地址",
        "city" | "town" => "城市",
        "state/province" | "province" | "stateprov" | "state or province" => "省/州",
        "postal code" | "zip code" | "postcode" | "postalcode" | "zipcode" => "邮政编码",
        "country code" => "国家/地区代码",
        "phone ext" => "电话分机",
        "ref" | "reference" => "参考",
        "referralserver" => "引荐服务器",
        "iana id" => "IANA ID",
        "whois" => "WHOIS 服务器",
        "registration status" => "注册状态",
        "registrant type" => "注册人类型",
        "registrant number" => "注册人编号",
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// 状态值中文注释

pub fn gloss_status(v: &str) -> Option<&'static str> {
    let first = v.split_whitespace().next().unwrap_or("");
    let lower = first.to_lowercase();
    Some(match lower.as_str() {
        "ok" => "正常",
        "active" => "活跃",
        "inactive" => "未激活",
        "clientdeleteprohibited" | "serverdeleteprohibited" => "禁止删除",
        "clienttransferprohibited" | "servertransferprohibited" => "禁止转移",
        "clientupdateprohibited" | "serverupdateprohibited" => "禁止更新",
        "clientrenewprohibited" | "serverrenewprohibited" => "禁止续费",
        "clienthold" | "serverhold" => "暂停解析",
        "pendingcreate" => "创建处理中",
        "pendingdelete" => "删除处理中",
        "pendingtransfer" => "转移处理中",
        "pendingupdate" => "更新处理中",
        "pendingrestore" => "恢复处理中",
        "pendingverification" => "验证待处理",
        "redemptionperiod" => "赎回期",
        "autorenewperiod" => "自动续费期",
        "renewperiod" => "续费宽限期",
        "transferperiod" => "转移期",
        "addperiod" => "注册宽限期",
        "reserved" => "保留",
        "assigned" => "已分配",
        "available" => "可注册",
        "unavailable" => "不可注册",
        "verified" => "已验证",
        "unverified" => "未验证",
        "locked" => "已锁定",
        "unlocked" => "未锁定",
        "direct allocation" => "直接分配",
        "direct assignment" => "直接指派",
        "reassigned" => "重新指派",
        "reallocated" => "重新分配",
        "legacy" => "历史资源",
        "infrastructure" => "基础设施",
        "assigned pa" => "已分配（PA）",
        "assigned pi" => "已分配（PI）",
        "allocated pa" => "已分配（PA）",
        "allocated unspecified" => "已分配",
        "lir-partitioned pa" => "LIR 分区（PA）",
        "sub-allocated pa" => "子分配（PA）",
        "early-registration" => "早期登记",
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// 值分类渲染

#[derive(Clone, Copy, PartialEq)]
enum KeyClass {
    Plain,
    Date,
    Email,
    Url,
    Ip,
    Ns,
    Status,
    Org,
    Handle,
    Phone,
}

fn classify_key(key: &str) -> KeyClass {
    match key {
        "creation date" | "created" | "registered" | "registration date" | "registration time"
        | "updated date" | "updated" | "last updated" | "last update" | "modified"
        | "last modified" | "creation" | "registry expiry date"
        | "registrar registration expiration date" | "expiry date" | "expiration date" | "expire"
        | "expires" | "paid-till" | "renewal date" | "regdate" | "free-date" | "deletion date"
        | "registered date" | "expiration time" | "last-modified" | "modify" | "registered on"
        | "domain expiration date" | "changed" => KeyClass::Date,
        "name server" | "nserver" | "nameserver" | "name servers" | "dns servers" | "dns server"
        | "primary server" | "secondary server" | "nserver handle" => KeyClass::Ns,
        "domain status" | "status" | "domainstatus" | "state" | "nettype" | "eligstatus"
        | "registration status" => KeyClass::Status,
        "registrant organization" | "registrant organisation" | "admin organization"
        | "tech organization" | "orgname" | "org-name" | "organisation" | "organization"
        | "org" | "owner" | "holder" | "registrar" | "sponsoring registrar" | "custname"
        | "network name" => KeyClass::Org,
        "nic-hdl" | "nic handle" | "handle" | "orgid" | "org id" | "registrant id" | "admin id"
        | "tech id" | "admin-c" | "tech-c" | "zone-c" | "holder-c" | "abuse-c" | "mntner"
        | "nethandle" | "orgtechhandle" | "orgnocshandle" | "orgabusehandle" | "rtechhandle"
        | "rnocshandle" | "rabusehandle" | "custhandle" | "registrar iana id"
        | "sponsoring registrar iana id" | "registry domain id" => KeyClass::Handle,
        "phone" | "phone number" | "voice" | "registrant phone" | "admin phone" | "tech phone"
        | "orgtechphone" | "orgabusephone" | "rtechphone" | "rnocsphone" | "rabusephone"
        | "custphone" | "holder phone" | "registrar phone" | "fax" | "fax-no" | "registrant fax"
        | "admin fax" | "tech fax" | "sponsoring registrar phone" => KeyClass::Phone,
        _ => {
            if key.contains("email") || key.contains("e-mail") || key.contains("mailbox") {
                KeyClass::Email
            } else if key.contains("url") || key.contains("whois server") || key == "whois" {
                KeyClass::Url
            } else if key == "inetnum" || key == "inet6num" || key == "netrange" || key == "cidr"
                || key == "originas" || key == "aut-num" || key == "origin" || key.contains("ip ")
                || key == "route" || key == "route6" || key == "as-name"
            {
                KeyClass::Ip
            } else {
                KeyClass::Plain
            }
        }
    }
}

fn is_probably_date(tok: &str) -> bool {
    let t = tok.trim_matches(['(', ')', ',', ';']);
    let mut digits = 0;
    let mut seps = 0;
    for c in t.chars() {
        if c.is_ascii_digit() {
            digits += 1;
        } else if matches!(c, '-' | '/' | '.' | ':') {
            seps += 1;
        } else {
            return false;
        }
    }
    digits >= 4 && digits <= 14 && seps >= 1 && seps <= 4
}

fn is_ip_token(tok: &str) -> bool {
    let t = tok.trim_matches(['(', ')', ',', ';']);
    if t.contains(':') && t.len() > 2 {
        return t.chars().filter(|c| *c == ':').count() >= 2
            && t.chars().all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.');
    }
    crate::server::myinet_aton(t).is_some()
}

/// 值语法高亮：邮箱、URL、IP、日期。
fn highlight_value(value: &str) -> String {
    let mut out = String::new();
    let mut rest = value;
    while let Some(pos) = rest.find(|c: char| {
        c == '@' || c == '.' || c == ':' || c.is_ascii_digit() || c == 'w'
    }) {
        out.push_str(&rest[..pos]);
        let token_end = rest[pos..]
            .find(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '[' | ']' | '"'))
            .map(|e| pos + e)
            .unwrap_or(rest.len());
        let tok = &rest[pos..token_end];
        let styled = if tok.contains('@') && tok.contains('.') && !tok.starts_with('@') {
            format!("{}{}{}", fg_email(), tok, reset())
        } else if tok.starts_with("http://")
            || tok.starts_with("https://")
            || tok.starts_with("www.")
        {
            format!("{}{}{}", fg_url(), tok, reset())
        } else if is_ip_token(tok) {
            format!("{}{}{}", fg_ip(), tok, reset())
        } else if is_probably_date(tok) {
            format!("{}{}{}", fg_date(), tok, reset())
        } else {
            tok.to_string()
        };
        out.push_str(&styled);
        rest = &rest[token_end..];
    }
    out.push_str(rest);
    out
}

fn style_for_class(class: KeyClass) -> &'static str {
    match class {
        KeyClass::Date => fg_date(),
        KeyClass::Email => fg_email(),
        KeyClass::Url => fg_url(),
        KeyClass::Ip => fg_ip(),
        KeyClass::Ns => fg_ns(),
        KeyClass::Org => fg_org(),
        KeyClass::Handle => fg_dim(),
        KeyClass::Phone => fg_value(),
        KeyClass::Plain | KeyClass::Status => fg_value(),
    }
}

/// 检测值是否被隐藏（GDPR 遮蔽等）。
fn is_redacted(value: &str) -> bool {
    let up = value.to_uppercase();
    up.contains("REDACTED") || up.contains("***") || up.contains("GDPR") || up.starts_with('*')
}

fn is_error_text(line: &str) -> bool {
    let l = line.to_lowercase();
    (l.contains("not found") || l.contains("no match") || l.contains("no entries found")
        || l.contains("no data found") || l.contains("nothing found") || l.contains("status: free")
        || l.contains("no object found") || l.contains("object not found")
        || l.contains("queried object not found") || l.contains("%error"))
        && l.len() < 120
}

// ---------------------------------------------------------------------------
// 原始输出（与 whois 完全一致的流式文本）

pub fn render_raw(events: &[Event], out: &mut String, err: &mut String) {
    for ev in events {
        match ev {
            Event::Message(m) => {
                let _ = writeln!(out, "{}", m);
            }
            Event::Error(m) => {
                let _ = writeln!(err, "{}", m);
            }
            Event::Notice(t) => {
                out.push_str(t);
                if !t.ends_with('\n') {
                    out.push('\n');
                }
            }
            Event::Verbose(t) => {
                let _ = writeln!(out, "{}", t);
            }
            Event::ReferralBanner(srv) => {
                let _ = writeln!(out, "\n\n发现一个到 {} 的引用。\n", srv);
            }
            Event::Response(resp) => {
                for line in &resp.lines {
                    let _ = writeln!(out, "{}", line);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 美化输出

pub struct PrettyOpts {
    pub width: usize,
    pub query: String,
    pub elapsed: std::time::Duration,
    pub show_hint: bool,
}

pub fn render_pretty(events: &[Event], po: &PrettyOpts, out: &mut String, err: &mut String) {
    let width = po.width.max(44).min(140);

    // 汇总统计
    let mut servers: Vec<&str> = Vec::new();
    let mut total_lines = 0usize;
    let mut n_queries = 0usize;
    for ev in events {
        if let Event::Response(r) = ev {
            n_queries += 1;
            total_lines += r.lines.len();
            if !servers.contains(&r.server.as_str()) {
                servers.push(r.server.as_str());
            }
        }
    }

    // 头部横幅
    let mut header_rows: Vec<String> = Vec::new();
    header_rows.push(format!(
        "🔍 查询对象   {}{}{}",
        fg_query(),
        po.query,
        reset()
    ));
    if !servers.is_empty() {
        let chain = servers
            .iter()
            .map(|s| format!("{}{}{}", fg_server(), s, reset()))
            .collect::<Vec<_>>()
            .join(&format!("{} → {}", reset(), fg_dim()));
        header_rows.push(format!("🌐 查询服务器 {}", chain));
    }
    header_rows.push(format!(
        "⏱  耗时     {:.2}s{}",
        po.elapsed.as_secs_f64(),
        reset()
    ));
    let header_w = header_rows
        .iter()
        .map(|r| str_width(&strip_ansi(r)) + 2)
        .max()
        .unwrap_or(0)
        + 6;
    draw_box(out, &header_rows, width.min(header_w.max(46)), BoxStyle::Double);

    let _ = writeln!(out);

    // 事件主体
    let mut first_section = true;
    let mut idx = 0usize;
    for ev in events {
        match ev {
            Event::Message(m) => {
                let styled = if m.starts_with("http://") || m.starts_with("https://") {
                    format!("  ➜ {}{}{}", fg_url(), m, reset())
                } else {
                    format!("  ⚠ {}{}{}", fg_error(), m, reset())
                };
                let _ = writeln!(out, "{}", styled);
            }
            Event::Notice(t) => {
                for l in t.lines().filter(|l| !l.is_empty()) {
                    let _ = writeln!(out, "  {}{}{}{}", fg_dim(), italic(), l, reset());
                }
            }
            Event::Verbose(t) => {
                let _ = writeln!(out, "  {}{}{}", fg_dim(), t, reset());
            }
            Event::Error(t) => {
                let _ = writeln!(err, "  {}{}{}{}", fg_error(), bold(), t, reset());
            }
            Event::ReferralBanner(srv) => {
                let _ = writeln!(
                    out,
                    "  {}{}{} ↳ 跟踪引荐 ➜ {}{}{}{}",
                    fg_frame(),
                    "─".repeat(4),
                    fg_banner(),
                    fg_server(),
                    srv,
                    reset(),
                    fg_frame()
                );
                let _ = writeln!(out, "{}", reset());
            }
            Event::Response(resp) => {
                idx += 1;
                if !first_section {
                    let _ = writeln!(out);
                }
                first_section = false;
                // 章节头
                let header = format!(
                    "▸ [{}/{}] {}{}{}",
                    idx,
                    n_queries,
                    fg_server(),
                    resp.server,
                    reset()
                );
                let qline = format!(
                    "  {}查询串{}  {}{}{}",
                    fg_dim(),
                    fg_dim(),
                    fg_dim(),
                    resp.query,
                    reset()
                );
                let _ = writeln!(out, "  {}{}{}", bold(), header, reset());
                let _ = writeln!(out, "  {}{}{}", fg_dim(), "─".repeat(width.saturating_sub(4).max(10)), reset());
                if crate::color::color_on() {
                    // 保持布局简单：查询串行内联显示
                }
                let _ = writeln!(out, "{}", qline);
                let _ = writeln!(out);
                render_response(resp, width, out);
            }
        }
    }

    // 页脚
    if po.show_hint {
        let _ = writeln!(out);
        let foot = format!(
            "📄 共 {} 行 · {} 次服务器查询 · 使用 --raw 查看原始输出",
            total_lines, n_queries
        );
        let _ = writeln!(out, "  {}{}{}", fg_dim(), foot, reset());
    }
}

#[derive(Clone, Copy, PartialEq)]
enum BoxStyle {
    Double,
}

fn draw_box(out: &mut String, rows: &[String], width: usize, style: BoxStyle) {
    let (tl, tr, bl, br, h, v) = match style {
        BoxStyle::Double => ("╔", "╗", "╚", "╝", "═", "║"),
    };
    let content_w = rows.iter().map(|r| str_width(r)).max().unwrap_or(0);
    let inner = width
        .saturating_sub(4)
        .max(content_w + 2)
        .min(140); // 两空格边距 + 两条竖线
    let _ = writeln!(out, "  {}{}{}{}{}", fg_frame(), tl, h.repeat(inner + 2), tr, reset());
    for row in rows {
        let content = format!(
            "  {} {} {}",
            v,
            pad_to(row, inner),
            v
        );
        let _ = writeln!(out, "{}{}", content, reset());
    }
    let _ = writeln!(out, "  {}{}{}{}{}", fg_frame(), bl, h.repeat(inner + 2), br, reset());
}

fn render_response(resp: &crate::server::Response, width: usize, out: &mut String) {
    let parsed: Parsed = parse::parse(&resp.lines);

    if parsed.objects.is_empty() {
        // 空响应
        let _ = writeln!(
            out,
            "  {}{}（服务器没有返回任何内容）{}",
            fg_dim(),
            italic(),
            reset()
        );
        return;
    }

    let mut card_count = 0;
    for obj in &parsed.objects {
        if obj.is_empty() {
            continue;
        }
        let has_pairs = obj.lines.iter().any(|l| matches!(l, Line::Pair { .. }));
        if !has_pairs {
            // 自由文本块：逐行原样输出（dim）
            for l in &obj.lines {
                if let Line::Raw(t) = l {
                    if is_error_text(t) {
                        let _ = writeln!(out, "  {}{}{}{}", fg_error(), bold(), t, reset());
                    } else {
                        let _ = writeln!(out, "  {}{}{}{}", fg_comment(), italic(), t.trim_end(), reset());
                    }
                }
            }
            continue;
        }
        if card_count > 0 {
            let _ = writeln!(out);
        }
        card_count += 1;
        render_card(obj, width, out);
    }
}

fn render_card(obj: &Object, width: usize, out: &mut String) {
    // ---------- 布局常量 ----------
    let margin = 2usize; // 卡片左边距
    let border = 2usize; // 左右竖线
    let pad_lr = 4usize; // 内容左右留白
    let kv_gap = 3usize; // 标签列与值列间距

    // ---------- 预渲染每一行 ----------
    enum Row {
        /// 注释/横幅等原始行（纯文本）
        Note(String),
        /// 键值行
        Pair {
            label_disp: String, // 已着色的标签
            label_w: usize,
            segs: Vec<String>, // 已着色、已按宽度换行的值片段
        },
    }

    let mut rows: Vec<Row> = Vec::new();
    for line in &obj.lines {
        match line {
            Line::Raw(t) => {
                let t = t.trim_end().to_string();
                if !t.is_empty() {
                    rows.push(Row::Note(t));
                }
            }
            Line::Pair { key, value } => {
                let class = classify_key(key);
                let redacted = is_redacted(value);
                let (label_disp, label_w) = match zh_label(key) {
                    Some(zh) => (
                        format!("{}{}{}", fg_label(), zh, reset()),
                        str_width(zh),
                    ),
                    None => (
                        format!("{}{}{}", fg_key(), key, reset()),
                        str_width(key),
                    ),
                };
                let styled = if class == KeyClass::Status {
                    style_status_value(value)
                } else if redacted {
                    format!("🔒 {}{}{}", fg_redacted(), value, reset())
                } else {
                    format!("{}{}{}", style_for_class(class), highlight_value(value), reset())
                };
                rows.push(Row::Pair {
                    label_disp,
                    label_w,
                    segs: vec![styled],
                });
            }
        }
    }
    if rows.is_empty() {
        return;
    }

    // ---------- 列宽 ----------
    let label_w = rows
        .iter()
        .filter_map(|r| match r {
            Row::Pair { label_w, .. } => Some(*label_w),
            _ => None,
        })
        .max()
        .unwrap_or(0)
        .max(4);

    let max_term = width.max(44).min(150);
    let card_outer = max_term.saturating_sub(margin).max(40); // 含边框的卡片宽

    // ---------- 卡片宽度（按未换行值的自然宽度） ----------
    let mut natural = 0usize;
    for r in &rows {
        match r {
            Row::Note(t) => natural = natural.max(str_width(t).min(card_outer / 2)),
            Row::Pair { segs, .. } => {
                let v = segs.iter().map(|s| str_width(&strip_ansi(s))).max().unwrap_or(0);
                natural = natural.max(label_w + kv_gap + v);
            }
        }
    }
    let (ty, title) = card_title(obj);
    let head_w = str_width(ty) + 2 + str_width(&title) + 8;
    let card_w = (natural + pad_lr + border)
        .max(head_w)
        .min(card_outer);
    let inner_w = card_w.saturating_sub(border + pad_lr).max(10);
    let value_w = inner_w.saturating_sub(label_w + kv_gap).max(8);

    // ---------- 值换行（最终宽度） ----------
    for r in rows.iter_mut() {
        if let Row::Pair { segs, .. } = r {
            let styled = std::mem::take(segs).pop().unwrap_or_default();
            let plain = strip_ansi(&styled);
            let mut new_segs: Vec<String> = Vec::new();
            for (i, part) in plain.split('\n').enumerate() {
                let wrapped = wrap_text(part, value_w);
                for wseg in wrapped {
                    // 逐段重新高亮，保持 ANSI 完整
                    if is_error_text(&plain) {
                        new_segs.push(format!("{}{}{}", fg_error(), wseg, reset()));
                    } else if styled.contains("🔒") {
                        new_segs.push(format!("🔒 {}{}{}", fg_redacted(), wseg, reset()));
                    } else {
                        let seg_styled = restyle_segment(&wseg, &plain, i > 0);
                        new_segs.push(seg_styled);
                    }
                }
            }
            if new_segs.is_empty() {
                new_segs.push(String::new());
            }
            *segs = new_segs;
        }
    }

    // ---------- 顶边 ----------
    let badge = format!(" {} ", ty);
    let title_part = if title.is_empty() {
        String::new()
    } else {
        format!(" {} ", title)
    };
    let head_used = str_width(&badge) + str_width(&title_part) + 4; // ╭─ 与 ─╮
    let head_fill = card_w.saturating_sub(head_used);
    let _ = writeln!(
        out,
        "  {}╭─{}{}{}{}{}{}─{}╮{}",
        fg_frame(),
        fg_badge(),
        badge,
        reset(),
        fg_title(),
        title_part,
        fg_frame(),
        "─".repeat(head_fill),
        reset()
    );

    // ---------- 行 ----------
    for r in &rows {
        match r {
            Row::Note(t) => {
                let wrapped = wrap_text(t, inner_w);
                for seg in &wrapped {
                    let body = format!("  {}{}{}{}", fg_comment(), italic(), seg, reset());
                    let line = format!(
                        "  {}│{}{}",
                        fg_frame(),
                        reset(),
                        pad_visible(&body, inner_w + 3),
                    );
                    let _ = writeln!(out, "{}│{}", line, reset());
                }
            }
            Row::Pair { label_disp, segs, .. } => {
                let lp = pad_visible(label_disp, label_w);
                for (i, seg) in segs.iter().enumerate() {
                    let content = if i == 0 {
                        format!("  {} {} {}", lp, " ".repeat(kv_gap.saturating_sub(1)), seg)
                    } else {
                        format!("  {} {} {}", " ".repeat(label_w), " ".repeat(kv_gap.saturating_sub(1)), seg)
                    };
                    let line = format!(
                        "  {}│{}{}",
                        fg_frame(),
                        reset(),
                        pad_visible(&content, inner_w + 3),
                    );
                    let _ = writeln!(out, "{}│{}", line, fg_frame());
                }
            }
        }
    }

    // ---------- 底边 ----------
    let _ = writeln!(
        out,
        "  {}╰{}╯{}",
        fg_frame(),
        "─".repeat(card_w.saturating_sub(3).max(4)),
        reset()
    );
}

/// 按可见宽度填充（忽略 ANSI 转义序列）。
fn pad_visible(s: &str, width: usize) -> String {
    let w = str_width(&strip_ansi(s));
    if w >= width {
        s.to_string()
    } else {
        format!("{}{}", s, " ".repeat(width - w))
    }
}

/// 值片段着色：参考整段原文的类别，按片段内容再次高亮。
fn restyle_segment(seg: &str, whole: &str, _cont: bool) -> String {
    let lower = whole.to_lowercase();
    if lower.contains('@') {
        return format!("{}{}{}", fg_email(), seg, reset());
    }
    format!("{}{}{}", fg_value(), seg, reset())
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'[' {
            i += 2;
            while i < bytes.len() && !bytes[i].is_ascii_alphabetic() {
                i += 1;
            }
            i += 1;
        } else {
            // 按 UTF-8 字符复制
            let ch_len = utf8_len(bytes[i]);
            out.push_str(&s[i..i + ch_len]);
            i += ch_len;
        }
    }
    out
}

fn utf8_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b >> 5 == 0b110 {
        2
    } else if b >> 4 == 0b1110 {
        3
    } else {
        4
    }
}

/// 按显示宽度换行；超长词硬截断。
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let width = width.max(4);
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut cur_w = 0usize;
    for word in text.split(' ') {
        let ww = str_width(word);
        if ww > width {
            // 先把当前行发出去
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
                cur_w = 0;
            }
            // 硬拆长词
            let mut buf = String::new();
            let mut buf_w = 0;
            for c in word.chars() {
                let cw = char_width(c);
                if buf_w + cw > width {
                    out.push(std::mem::take(&mut buf));
                    buf_w = 0;
                }
                buf.push(c);
                buf_w += cw;
            }
            if !buf.is_empty() {
                cur = buf;
                cur_w = buf_w;
            }
            continue;
        }
        if cur_w + ww + usize::from(!cur.is_empty()) > width && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
            cur_w = 0;
        }
        if !cur.is_empty() {
            cur.push(' ');
            cur_w += 1;
        }
        cur.push_str(word);
        cur_w += ww;
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

fn card_title(obj: &Object) -> (&'static str, String) {
    let ty = parse::object_type(obj);
    let title = parse::object_title(obj).unwrap_or_default();
    let title = truncate_width(&title, 46);
    (ty, title)
}

/// 状态值着色：彩色圆点 + 中文注释 + 原始值。
fn style_status_value(value: &str) -> String {
    let first = value.split_whitespace().next().unwrap_or("");
    let lower = first.to_lowercase();
    let color = match lower.as_str() {
        "ok" | "active" | "assigned" | "registered" | "available" | "verified" | "unlocked" => {
            fg_status_ok()
        }
        "inactive" | "pendingcreate" | "pendingdelete" | "pendingtransfer" | "pendingupdate"
        | "pendingrestore" | "pendingverification" | "redemptionperiod" | "autorenewperiod"
        | "renewperiod" | "transferperiod" | "addperiod" | "clienthold" | "serverhold" => {
            fg_status_warn()
        }
        "" => fg_value(),
        _ => {
            if lower.contains("prohibited") || lower.contains("hold") || lower.contains("locked")
                || lower.contains("reserved") || lower.contains("unavailable")
            {
                fg_status_warn()
            } else {
                fg_value()
            }
        }
    };
    let mut out = String::new();
    if !first.is_empty() {
        out.push_str(color);
        out.push('●');
        out.push(' ');
        out.push_str(first);
        out.push_str(reset());
        if let Some(gloss) = gloss_status(value) {
            out.push_str(&format!(" {}（{}）{}", fg_dim(), gloss, reset()));
        }
        let rest = &value[first.len()..];
        if !rest.trim().is_empty() {
            out.push(' ');
            out.push_str(&highlight_value(rest.trim()));
        }
    } else {
        out.push_str(&highlight_value(value));
    }
    out
}
