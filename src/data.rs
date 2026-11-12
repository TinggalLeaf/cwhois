// 嵌入数据表 —— 移植自 whois（rfc1036/whois）发行版中的
// tld_serv_list / ip_del_list / ip_del_recovered.h / ip6_del_list /
// as_del_list / new_gtlds_list / nic_handles_list / data.h。
// 服务器字符串可能以控制字符开头（与 C 源码的编码方式一致）：
//   \x01 = WEB（无 whois 服务器，只有网页，其后为 URL）
//   \x03 = NONE（该 TLD 没有 whois 服务器）
//   \x04 = VERISIGN（使用 "domain " 前缀查询）
//   \x05 = 不知道此对象类型的 whois 服务器
//   \x06 = 未知 AS 号或 IP 网络
//   \x08 = RECURSIVE（跟踪注册商 whois 服务器引荐）
//   \x0C = in-addr.arpa 反查转换   \x0D = ip6.arpa 反查转换
//   \x0A = 6to4 转换   \x0B = Teredo 转换   \x0E = 强制 whois.iana.org

/// TLD → whois 服务器（最先匹配优先）。服务器名不带点时会补 whois./.net。
pub const TLD_SERV: &[(&str, &str)] = &[
    ("br.com", "whois.centralnic.net"),
    ("cn.com", "whois.centralnic.net"),
    ("de.com", "whois.centralnic.net"),
    ("eu.com", "whois.centralnic.net"),
    ("gb.com", "whois.centralnic.net"),
    ("gb.net", "whois.centralnic.net"),
    ("gr.com", "whois.centralnic.net"),
    ("hu.com", "whois.centralnic.net"),
    ("in.net", "whois.centralnic.net"),
    ("no.com", "whois.centralnic.net"),
    ("qc.com", "whois.centralnic.net"),
    ("ru.com", "whois.centralnic.net"),
    ("sa.com", "whois.centralnic.net"),
    ("se.com", "whois.centralnic.net"),
    ("se.net", "whois.centralnic.net"),
    ("uk.com", "whois.centralnic.net"),
    ("uk.net", "whois.centralnic.net"),
    ("us.com", "whois.centralnic.net"),
    ("uy.com", "whois.centralnic.net"),
    ("za.com", "whois.centralnic.net"),
    ("jpn.com", "whois.centralnic.net"),
    ("web.com", "whois.centralnic.net"),
    ("com", "\u{4}whois.verisign-grs.com"),
    ("za.net", "whois.za.net"),
    ("net", "\u{4}whois.verisign-grs.com"),
    ("eu.org", "whois.eu.org"),
    ("za.org", "whois.za.org"),
    ("org", "whois.pir.org"),
    ("llyw.cymru", "whois.nic.llyw.cymru"),
    ("gov.scot", "whois.nic.gov.scot"),
    ("gov.wales", "whois.nic.gov.wales"),
    ("edu", "whois.educause.edu"),
    ("gov", "whois.nic.gov"),
    ("int", "whois.iana.org"),
    ("mil", "\u{3}"),
    ("e164.arpa", "whois.ripe.net"),
    ("in-addr.arpa", "\u{c}"),
    ("ip6.arpa", "\u{d}"),
    ("arpa", "whois.iana.org"),
    ("aero", "whois.aero"),
    ("asia", "whois.nic.asia"),
    ("biz", "whois.nic.biz"),
    ("cat", "whois.nic.cat"),
    ("coop", "whois.nic.coop"),
    ("info", "\u{3}"),
    ("jobs", "\u{3}"),
    ("mobi", "\u{3}"),
    ("museum", "whois.nic.museum"),
    ("name", "whois.nic.name"),
    ("post", "whois.nic.post"),
    ("pro", "\u{3}"),
    ("tel", "whois.nic.tel"),
    ("travel", "\u{3}"),
    ("xxx", "whois.nic.xxx"),
    ("ac", "whois.nic.ac"),
    ("ad", "whois.nic.ad"),
    ("ae", "whois.aeda.net.ae"),
    ("af", "whois.nic.af"),
    ("ag", "whois.nic.ag"),
    ("ai", "whois.nic.ai"),
    ("al", "\u{3}"),
    ("am", "whois.amnic.net"),
    ("ao", "\u{1}https://www.dns.ao/ao/whois/"),
    ("aq", "\u{3}"),
    ("ar", "whois.nic.ar"),
    ("as", "whois.nic.as"),
    ("priv.at", "whois.nic.priv.at"),
    ("at", "whois.nic.at"),
    ("au", "whois.auda.org.au"),
    ("aw", "whois.nic.aw"),
    ("ax", "whois.ax"),
    ("gov.az", "\u{1}https://www.gov.az/"),
    ("az", "\u{1}https://whois.az/"),
    ("ba", "\u{1}https://nic.ba/"),
    ("bb", "\u{1}https://whois.telecoms.gov.bb/"),
    ("bd", "\u{1}https://bdia.btcl.com.bd/"),
    ("be", "whois.dns.be"),
    ("bf", "whois.registre.bf"),
    ("bg", "whois.register.bg"),
    ("bh", "whois.nic.bh"),
    ("bi", "whois1.nic.bi"),
    ("bj", "whois.nic.bj"),
    ("bm", "whois.nic.bm"),
    ("bn", "whois.bnnic.bn"),
    ("bo", "whois.nic.bo"),
    ("br", "whois.registro.br"),
    ("bs", "\u{3}"),
    ("bt", "\u{1}http://www.nic.bt/"),
    ("bv", "\u{3}"),
    ("by", "whois.cctld.by"),
    ("bw", "whois.nic.net.bw"),
    ("bz", "\u{8}whois.identitydigital.services"),
    ("co.ca", "whois.co.ca"),
    ("ca", "whois.cira.ca"),
    ("cc", "\u{4}ccwhois.verisign-grs.com"),
    ("cd", "whois.nic.cd"),
    ("cf", "\u{3}"),
    ("cg", "\u{3}"),
    ("ch", "whois.nic.ch"),
    ("ci", "whois.nic.ci"),
    ("ck", "\u{3}"),
    ("cl", "whois.nic.cl"),
    ("cm", "whois.nic.cm"),
    ("edu.cn", "whois.edu.cn"),
    ("cn", "whois.cnnic.cn"),
    ("uk.co", "whois.uk.co"),
    ("co", "whois.registry.co"),
    ("cr", "whois.nic.cr"),
    ("cu", "\u{1}https://www.nic.cu/"),
    ("cv", "whois.nic.cv"),
    ("cw", "\u{3}"),
    ("cx", "whois.nic.cx"),
    ("cy", "\u{1}https://www.nic.cy/cy-ui/home"),
    ("cz", "whois.nic.cz"),
    ("de", "whois.denic.de"),
    ("dj", "\u{3}"),
    ("dk", "whois.punktum.dk"),
    ("dm", "whois.dmdomains.dm"),
    ("do", "whois.nic.do"),
    ("dz", "whois.nic.dz"),
    ("ec", "whois.nic.ec"),
    ("ee", "whois.tld.ee"),
    ("eg", "\u{3}"),
    ("es", "\u{1}https://www.dominios.es/en"),
    ("et", "\u{3}"),
    ("eu", "whois.eu"),
    ("fi", "whois.fi"),
    ("fj", "www.whois.fj"),
    ("fk", "\u{3}"),
    ("fm", "whois.nic.fm"),
    ("fo", "whois.nic.fo"),
    ("fr", "whois.nic.fr"),
    ("ga", "whois.nic.ga"),
    ("gd", "whois.nic.gd"),
    ("ge", "whois.nic.ge"),
    ("gf", "whois.mediaserv.net"),
    ("gg", "whois.gg"),
    ("gh", "whois.nic.gh"),
    ("gi", "whois.identitydigital.services"),
    ("gl", "whois.nic.gl"),
    ("gm", "\u{1}http://www.nic.gm/htmlpages/whois.htm"),
    ("gn", "whois.ande.gov.gn"),
    ("gp", "whois.nic.gp"),
    ("gq", "\u{1}http://www.dominio.gq/en/whois.html"),
    ("gr", "\u{1}https://grweb.ics.forth.gr/public/whois?lang=en"),
    ("gs", "whois.nic.gs"),
    ("gt", "\u{1}https://www.gt/sitio/?lang=en"),
    ("gu", "\u{3}"),
    ("gw", "\u{1}https://registar.nic.gw/en/whois/"),
    ("gy", "whois.registry.gy"),
    ("hk", "whois.hkirc.hk"),
    ("hm", "whois.registry.hm"),
    ("hn", "whois.nic.hn"),
    ("hr", "whois.dns.hr"),
    ("ht", "whois.nic.ht"),
    ("hu", "whois.nic.hu"),
    ("id", "whois.id"),
    ("ie", "whois.weare.ie"),
    ("il", "whois.isoc.org.il"),
    ("im", "whois.nic.im"),
    ("in", "\u{8}whois.nixiregistry.in"),
    ("iq", "whois.cmc.iq"),
    ("ir", "whois.nic.ir"),
    ("is", "whois.isnic.is"),
    ("it", "whois.nic.it"),
    ("je", "whois.je"),
    ("jm", "\u{3}"),
    ("jo", "\u{1}https://www.domain.jo/FirstPageen.aspx"),
    ("jp", "whois.jprs.jp"),
    ("ke", "whois.kenic.or.ke"),
    ("kg", "whois.kg"),
    ("kh", "\u{3}"),
    ("ki", "whois.nic.ki"),
    ("km", "\u{3}"),
    ("kn", "whois.nic.kn"),
    ("kp", "\u{3}"),
    ("kr", "whois.kr"),
    ("kw", "whois.nic.kw"),
    ("ky", "whois.kyregistry.ky"),
    ("kz", "whois.nic.kz"),
    ("la", "whois.nic.la"),
    ("lb", "whois.lbdr.org.lb"),
    ("lc", "\u{8}whois.identitydigital.services"),
    ("li", "whois.nic.li"),
    ("lk", "whois.nic.lk"),
    ("lr", "\u{3}"),
    ("ls", "whois.nic.ls"),
    ("lt", "whois.domreg.lt"),
    ("lu", "whois.dns.lu"),
    ("lv", "whois.nic.lv"),
    ("ly", "whois.nic.ly"),
    ("ma", "whois.registre.ma"),
    ("mc", "whois.nic.mc"),
    ("md", "whois.nic.md"),
    ("me", "\u{8}whois.nic.me"),
    ("mg", "whois.nic.mg"),
    ("mh", "\u{3}"),
    ("mk", "whois.marnet.mk"),
    ("ml", "whois.nic.ml"),
    ("mm", "whois.registry.gov.mm"),
    ("mn", "whois.nic.mn"),
    ("mo", "\u{1}https://www.monic.mo/monic/faces/whois"),
    ("mp", "\u{3}"),
    ("mq", "whois.mediaserv.net"),
    ("mr", "whois.nic.mr"),
    ("ms", "whois.nic.ms"),
    ("mt", "whois.nic.org.mt"),
    ("mu", "whois.tld.mu"),
    ("mv", "\u{3}"),
    ("mw", "whois.nic.mw"),
    ("mx", "whois.mx"),
    ("my", "whois.mynic.my"),
    ("mz", "whois.nic.mz"),
    ("na", "whois.na-nic.com.na"),
    ("nc", "whois.nc"),
    ("ne", "\u{3}"),
    ("nf", "whois.nic.nf"),
    ("ng", "whois.nic.net.ng"),
    ("ni", "\u{1}https://www.nic.ni/"),
    ("nl", "whois.domain-registry.nl"),
    ("no", "whois.norid.no"),
    ("np", "\u{1}https://register.com.np/whois-lookup"),
    ("nr", "\u{1}https://www.cenpac.net.nr/dns/whois.html"),
    ("nu", "whois.iis.nu"),
    ("nz", "whois.irs.net.nz"),
    ("om", "whois.registry.om"),
    ("pa", "\u{1}http://www.nic.pa/en"),
    ("pe", "kero.yachay.pe"),
    ("pf", "whois.registry.pf"),
    ("pg", "whois.nic.pg"),
    ("edu.ph", "\u{1}https://services.ph.net/dnshosting/dnshostingquery.pl"),
    ("gov.ph", "\u{3}"),
    ("ph", "\u{1}https://whois.dot.ph/"),
    ("pk", "whois.pknic.net.pk"),
    ("co.pl", "whois.co.pl"),
    ("pl", "whois.dns.pl"),
    ("pm", "whois.nic.pm"),
    ("pn", "\u{1}https://www.nic.pn/"),
    ("pr", "\u{8}whois.nic.pr"),
    ("ps", "\u{1}https://www.pnina.ps/"),
    ("pt", "whois.dns.pt"),
    ("pw", "whois.nic.pw"),
    ("py", "\u{1}https://www.nic.py/consultdompy.php"),
    ("qa", "whois.registry.qa"),
    ("re", "whois.nic.re"),
    ("ro", "whois.rotld.ro"),
    ("rs", "whois.rnids.rs"),
    ("ac.ru", "whois.free.net"),
    ("edu.ru", "whois.informika.ru"),
    ("com.ru", "\u{8}whois.flexireg.net"),
    ("msk.ru", "\u{8}whois.flexireg.net"),
    ("net.ru", "whois.nic.net.ru"),
    ("nov.ru", "\u{8}whois.flexireg.net"),
    ("org.ru", "whois.nic.net.ru"),
    ("pp.ru", "whois.nic.net.ru"),
    ("spb.ru", "\u{8}whois.flexireg.net"),
    ("ru", "whois.tcinet.ru"),
    ("rw", "whois.ricta.org.rw"),
    ("sa", "whois.nic.net.sa"),
    ("sb", "whois.nic.net.sb"),
    ("sc", "whois.nic.sc"),
    ("sd", "whois.nic.sd"),
    ("se", "whois.iis.se"),
    ("sg", "whois.sgnic.sg"),
    ("sh", "whois.nic.sh"),
    ("si", "whois.register.si"),
    ("sj", "\u{3}"),
    ("sk", "whois.sk-nic.sk"),
    ("sl", "whois.nic.sl"),
    ("sm", "whois.nic.sm"),
    ("sn", "whois.nic.sn"),
    ("so", "whois.nic.so"),
    ("sr", "whois.sr"),
    ("ss", "whois.nic.ss"),
    ("st", "whois.nic.st"),
    ("msk.su", "\u{8}whois.flexireg.net"),
    ("nov.su", "\u{8}whois.flexireg.net"),
    ("spb.su", "\u{8}whois.flexireg.net"),
    ("su", "whois.tcinet.ru"),
    ("sv", "\u{1}https://svnet.sv/"),
    ("sx", "whois.sx"),
    ("sy", "whois.tld.sy"),
    ("sz", "\u{3}"),
    ("tc", "whois.nic.tc"),
    ("td", "whois.nic.td"),
    ("tf", "whois.nic.tf"),
    ("tg", "whois.nic.tg"),
    ("th", "whois.thnic.co.th"),
    ("tj", "\u{1}http://www.nic.tj/whois.html"),
    ("tk", "whois.dot.tk"),
    ("tl", "whois.nic.tl"),
    ("tm", "whois.nic.tm"),
    ("tn", "whois.ati.tn"),
    ("to", "whois.tonicregistry.to"),
    ("tr", "whois.trabis.gov.tr"),
    ("tt", "\u{1}https://www.nic.tt/cgi-bin/search.pl"),
    ("tv", "\u{8}whois.nic.tv"),
    ("tw", "whois.twnic.net.tw"),
    ("tz", "whois.tznic.or.tz"),
    ("biz.ua", "whois.biz.ua"),
    ("co.ua", "whois.co.ua"),
    ("pp.ua", "whois.pp.ua"),
    ("ua", "whois.ua"),
    ("ug", "whois.co.ug"),
    ("ac.uk", "whois.nic.ac.uk"),
    ("gov.uk", "whois.gov.uk"),
    ("mil.uk", "\u{3}"),
    ("mod.uk", "\u{3}"),
    ("nhs.uk", "\u{3}"),
    ("parliament.uk", "\u{3}"),
    ("uk", "whois.nic.uk"),
    ("fed.us", "whois.nic.gov"),
    ("us", "whois.nic.us"),
    ("gub.uy", "\u{1}https://www.dominios.gub.uy/"),
    ("mil.uy", "\u{1}https://www.dominios.gub.uy/"),
    ("uy", "\u{1}https://www.nic.uy/"),
    ("uz", "whois.cctld.uz"),
    ("va", "\u{3}"),
    ("vc", "\u{8}whois.identitydigital.services"),
    ("ve", "whois.nic.ve"),
    ("vg", "whois.nic.vg"),
    ("vi", "whois.nic.vi"),
    ("vn", "\u{1}http://www.vnnic.vn/en"),
    ("vu", "whois.dnrs.vu"),
    ("wf", "whois.nic.wf"),
    ("ws", "whois.website.ws"),
    ("ye", "whois.y.net.ye"),
    ("yt", "whois.nic.yt"),
    ("ac.za", "whois.ac.za"),
    ("alt.za", "\u{1}https://whois.alt.za/"),
    ("co.za", "whois.registry.net.za"),
    ("edu.za", "\u{1}https://whois.edu.za/"),
    ("gov.za", "whois.gov.za"),
    ("net.za", "net-whois.registry.net.za"),
    ("org.za", "org-whois.registry.net.za"),
    ("web.za", "web-whois.registry.net.za"),
    ("za", "whois.nic.za"),
    ("zm", "whois.zicta.zm"),
    ("zw", "\u{3}"),
    // IDN ccTLD（ Punycode 形式）
    ("xn--2scrj9c", "whois.nixiregistry.in"),
    ("xn--3e0b707e", "whois.kr"),
    ("xn--3hcrj9c", "whois.nixiregistry.in"),
    ("xn--45br5cyl", "whois.nixiregistry.in"),
    ("xn--45brj9c", "whois.nixiregistry.in"),
    ("xn--4dbrk0ce", "whois.isoc.org.il"),
    ("xn--54b7fta0cc", "\u{1}https://bdia.btcl.com.bd/"),
    ("xn--80ao21a", "whois.nic.kz"),
    ("xn--90a3ac", "whois.rnids.rs"),
    ("xn--90ae", "whois.imena.bg"),
    ("xn--90ais", "whois.cctld.by"),
    ("xn--clchc0ea0b2g2a9gcd", "whois.ta.sgnic.sg"),
    ("xn--d1alf", "whois.marnet.mk"),
    ("xn--e1a4c", "whois.eu"),
    ("xn--fiqs8s", "whois.cnnic.cn"),
    ("xn--fiqz9s", "whois.cnnic.cn"),
    ("xn--fpcrj9c3d", "whois.nixiregistry.in"),
    ("xn--fzc2c9e2c", "whois.nic.lk"),
    ("xn--gecrj9c", "whois.nixiregistry.in"),
    ("xn--h2breg3eve", "whois.nixiregistry.in"),
    ("xn--h2brj9c8c", "whois.nixiregistry.in"),
    ("xn--h2brj9c", "whois.nixiregistry.in"),
    ("xn--j1amh", "whois.dotukr.com"),
    ("xn--j6w193g", "whois.hkirc.hk"),
    ("xn--kprw13d", "whois.twnic.net.tw"),
    ("xn--kpry57d", "whois.twnic.net.tw"),
    ("xn--l1acc", "whois.mn"),
    ("xn--lgbbat1ad8j", "whois.nic.dz"),
    ("xn--mgb9awbf", "whois.registry.om"),
    ("xn--mgba3a4f16a", "whois.nic.ir"),
    ("xn--mgbaam7a8h", "whois.aeda.net.ae"),
    ("xn--mgbah1a3hjkrd", "whois.nic.mr"),
    ("xn--mgbai9azgqp6j", "\u{3}"),
    ("xn--mgbayh7gpa", "\u{1}https://www.domain.jo/FirstPageen.aspx"),
    ("xn--mgbbh1a71e", "whois.nixiregistry.in"),
    ("xn--mgbbh1a", "whois.nixiregistry.in"),
    ("xn--mgbc0a9azcg", "\u{3}"),
    ("xn--mgbcpq6gpa1a", "\u{3}"),
    ("xn--mgberp4a5d4ar", "whois.nic.net.sa"),
    ("xn--mgbgu82a", "whois.nixiregistry.in"),
    ("xn--mgbpl2fh", "\u{3}"),
    ("xn--mgbtx2b", "whois.cmc.iq"),
    ("xn--mgbx4cd0ab", "whois.mynic.my"),
    ("xn--mix891f", "\u{1}https://www.monic.mo/monic/faces/whois"),
    ("xn--node", "\u{1}http://რეგისტრაცია.გე/"),
    ("xn--o3cw4h", "whois.thnic.co.th"),
    ("xn--ogbpf8fl", "whois.tld.sy"),
    ("xn--p1ai", "whois.tcinet.ru"),
    ("xn--pgbs0dh", "whois.ati.tn"),
    ("xn--q7ce6a", "whois.nic.la"),
    ("xn--qxa6a", "whois.eu"),
    ("xn--qxam", "\u{1}https://grweb.ics.forth.gr/public/whois?lang=en"),
    ("xn--rvc1e0am3e", "whois.nixiregistry.in"),
    ("xn--s9brj9c", "whois.nixiregistry.in"),
    ("xn--wgbh1c", "whois.dotmasr.eg"),
    ("xn--wgbl6a", "whois.registry.qa"),
    ("xn--xkc2al3hye2a", "whois.nic.lk"),
    ("xn--xkc2dl3a5ee0h", "whois.nixiregistry.in"),
    ("xn--y9a3aq", "whois.amnic.net"),
    ("xn--yfro4i67o", "whois.zh.sgnic.sg"),
    ("xn--ygbi2ammx", "\u{3}"),
];

/// NIC 句柄前缀 → whois 服务器
pub const NIC_HANDLES: &[(&str, &str)] = &[
    ("net-", "whois.arin.net"),
    ("netblk-", "whois.arin.net"),
    ("poem-", "whois.ripe.net"),
    ("form-", "whois.ripe.net"),
    ("pgpkey-", "whois.ripe.net"),
    ("denic-", "whois.denic.de"),
    ("as-", "whois.ripe.net"),
    ("rs-", "whois.ripe.net"),
    ("rtrs-", "whois.ripe.net"),
    ("fltr-", "whois.ripe.net"),
    ("prng-", "whois.ripe.net"),
];

/// NIC 句柄后缀 → whois 服务器
pub const NIC_HANDLES_POST: &[(&str, &str)] = &[
    ("-arin", "whois.arin.net"),
    ("-ripe", "whois.ripe.net"),
    ("-mnt", "whois.ripe.net"),
    ("-lacnic", "whois.lacnic.net"),
    ("-afrinic", "whois.afrinic.net"),
    ("-ap", "whois.apnic.net"),
    ("-cznic", "whois.nic.cz"),
    ("-dk", "whois.punktum.dk"),
    ("-il", "whois.isoc.org.il"),
    ("-is", "whois.isnic.is"),
    ("-kg", "whois.kg"),
    ("-coop", "whois.nic.coop"),
    ("-frnic", "whois.nic.fr"),
    ("-lrms", "whois.afilias.info"),
    ("-nicat", "whois.nic.at"),
    ("-nicci", "whois.nic.ci"),
    ("-irnic", "whois.nic.ir"),
    ("-norid", "whois.norid.no"),
    ("-tel", "whois.nic.tel"),
    ("-adnic", "whois.nic.org.uy"),
    ("-sixxs", "whois.sixxs.net"),
    ("-uanic", "whois.ua"),
    ("-bzh", "whois.nic.bzh"),
    ("-ru", "whois.tcinet.ru"),
    ("-su", "whois.tcinet.ru"),
];

/// 支持 RIPE 风格查询标志的服务器
pub const RIPE_SERVERS: &[&str] = &[
    "whois.ripe.net",
    "whois.apnic.net",
    "whois.afrinic.net",
    "rr.arin.net",
    "rr.level3.net",
    "rr.ntt.net",
    "whois.tcinet.ru",
    "whois.ripn.net",
    "whois.register.si",
    "whois.nic.ir",
];

/// IPv6 段表：(起始地址前 32 位, 掩码长度, 服务器)。先匹配优先。
/// "\u{a}" = 6to4 转换，"\u{b}" = Teredo 转换。
pub const IP6_ASSIGN: &[(u32, u8, &str)] = &[
    (0x20010000, 32, "\u{b}"),
    (0x20010200, 23, "whois.apnic.net"),
    (0x20010400, 23, "whois.arin.net"),
    (0x20010600, 23, "whois.ripe.net"),
    (0x20010800, 22, "whois.ripe.net"),
    (0x20010c00, 22, "whois.apnic.net"),
    (0x20011000, 22, "whois.lacnic.net"),
    (0x20011400, 22, "whois.ripe.net"),
    (0x20011800, 23, "whois.arin.net"),
    (0x20011a00, 23, "whois.ripe.net"),
    (0x20011c00, 22, "whois.ripe.net"),
    (0x20012000, 19, "whois.ripe.net"),
    (0x20014000, 23, "whois.ripe.net"),
    (0x20014200, 23, "whois.afrinic.net"),
    (0x20014400, 23, "whois.apnic.net"),
    (0x20014600, 23, "whois.ripe.net"),
    (0x20014800, 23, "whois.arin.net"),
    (0x20014a00, 23, "whois.ripe.net"),
    (0x20014c00, 22, "whois.ripe.net"),
    (0x20015000, 20, "whois.ripe.net"),
    (0x20018000, 18, "whois.apnic.net"),
    (0x20020000, 16, "\u{a}"),
    (0x20030000, 18, "whois.ripe.net"),
    (0x24000000, 20, "whois.nic.or.kr"),
    (0x24000000, 11, "whois.apnic.net"),
    (0x26000000, 12, "whois.arin.net"),
    (0x26100000, 23, "whois.arin.net"),
    (0x26200000, 23, "whois.arin.net"),
    (0x26300000, 12, "whois.arin.net"),
    (0x28000000, 12, "whois.lacnic.net"),
    (0x2a000000, 11, "whois.ripe.net"),
    (0x2c000000, 12, "whois.afrinic.net"),
];

/// ASN 分配表：(起始 ASN, 结束 ASN, 服务器)。先匹配优先。
/// 支持 16 位 ASN；32 位 ASN 使用 (高16位<<16)+低16位 编码（如 "2.0"）。
pub const AS_ASSIGN: &[(u32, u32, &str)] = &[
    (248, 251, "whois.ripe.net"),
    (306, 371, "whois.nic.mil"),
    (379, 508, "whois.nic.mil"),
    (1101, 1200, "whois.ripe.net"),
    (1267, 1275, "whois.ripe.net"),
    (1877, 1901, "whois.ripe.net"),
    (2043, 2043, "whois.ripe.net"),
    (2047, 2047, "whois.ripe.net"),
    (2057, 2136, "whois.ripe.net"),
    (2387, 2488, "whois.ripe.net"),
    (2497, 2528, "whois.nic.ad.jp"),
    (2585, 2614, "whois.ripe.net"),
    (2773, 2822, "whois.ripe.net"),
    (2830, 2879, "whois.ripe.net"),
    (3154, 3353, "whois.ripe.net"),
    (4608, 4864, "whois.apnic.net"),
    (5120, 5376, "whois.nic.mil"),
    (5377, 5631, "whois.ripe.net"),
    (5800, 6055, "whois.nic.mil"),
    (6656, 6911, "whois.ripe.net"),
    (7467, 7722, "whois.apnic.net"),
    (8192, 9215, "whois.ripe.net"),
    (9591, 9622, "whois.nic.ad.jp"),
    (9628, 9647, "whois.nic.or.kr"),
    (9683, 9712, "whois.nic.or.kr"),
    (9753, 9784, "whois.nic.or.kr"),
    (9840, 9871, "whois.nic.or.kr"),
    (9943, 9982, "whois.nic.or.kr"),
    (9990, 10021, "whois.nic.ad.jp"),
    (10034, 10073, "whois.nic.or.kr"),
    (10154, 10198, "whois.nic.or.kr"),
    (9216, 10239, "whois.apnic.net"),
    (12288, 13311, "whois.ripe.net"),
    (15360, 16383, "whois.ripe.net"),
    (17503, 17534, "whois.nic.ad.jp"),
    (17567, 17616, "whois.nic.or.kr"),
    (17673, 17704, "whois.nic.ad.jp"),
    (17832, 17881, "whois.nic.or.kr"),
    (17930, 17961, "whois.nic.ad.jp"),
    (18067, 18098, "whois.nic.ad.jp"),
    (18121, 18152, "whois.nic.ad.jp"),
    (18259, 18290, "whois.nic.ad.jp"),
    (18294, 18343, "whois.nic.or.kr"),
    (17408, 18431, "whois.apnic.net"),
    (20480, 21503, "whois.ripe.net"),
    (23552, 23601, "whois.nic.or.kr"),
    (23612, 23643, "whois.nic.ad.jp"),
    (23773, 23836, "whois.nic.ad.jp"),
    (24248, 24297, "whois.nic.ad.jp"),
    (23552, 24575, "whois.apnic.net"),
    (24576, 25599, "whois.ripe.net"),
    (26592, 26623, "whois.lacnic.net"),
    (27648, 28671, "whois.lacnic.net"),
    (28672, 29695, "whois.ripe.net"),
    (30980, 30999, "whois.afrinic.net"),
    (30720, 31743, "whois.ripe.net"),
    (34515, 34519, "whois.afrinic.net"),
    (33792, 35839, "whois.ripe.net"),
    (36864, 37887, "whois.afrinic.net"),
    (37888, 37927, "whois.nic.ad.jp"),
    (38086, 38135, "whois.nic.or.kr"),
    (38387, 38436, "whois.nic.or.kr"),
    (38627, 38656, "whois.nic.ad.jp"),
    (38660, 38709, "whois.nic.or.kr"),
    (37888, 38911, "whois.apnic.net"),
    (38912, 39935, "whois.ripe.net"),
    (40960, 45055, "whois.ripe.net"),
    (45360, 45409, "whois.nic.or.kr"),
    (45672, 45691, "whois.nic.ad.jp"),
    (45963, 46012, "whois.nic.or.kr"),
    (45056, 46079, "whois.apnic.net"),
    (47104, 52223, "whois.ripe.net"),
    (52224, 53247, "whois.lacnic.net"),
    (55372, 55396, "whois.nic.ad.jp"),
    (55584, 55633, "whois.nic.or.kr"),
    (55888, 55912, "whois.nic.ad.jp"),
    (55296, 56319, "whois.apnic.net"),
    (56320, 58367, "whois.ripe.net"),
    (58645, 58654, "whois.nic.ad.jp"),
    (58784, 58793, "whois.nic.ad.jp"),
    (59091, 59130, "whois.nic.ad.jp"),
    (58368, 59391, "whois.apnic.net"),
    (59392, 61439, "whois.ripe.net"),
    (61440, 61951, "whois.lacnic.net"),
    (61952, 62463, "whois.ripe.net"),
    (63488, 64098, "whois.apnic.net"),
    (64099, 64197, "whois.lacnic.net"),
    // 兜底：其余全部归 ARIN
    (1, 64296, "whois.arin.net"),
    (64297, 64395, "whois.apnic.net"),
    (64396, 64495, "whois.ripe.net"),
    // 文档与私有 ASN 段
    (64496, 65534, "whois.ripe.net"),
    (131077, 131086, "whois.nic.ad.jp"),
    (131092, 131101, "whois.nic.or.kr"),
    (131152, 131161, "whois.nic.ad.jp"),
    (131791, 131890, "whois.nic.or.kr"),
    (131893, 131992, "whois.nic.ad.jp"),
    // 各 RIR 保留的未分配空间（32 位 ASN，点分记法）
    (2 << 16, (2 << 16) + 65535, "whois.apnic.net"),
    (3 << 16, (3 << 16) + 65535, "whois.ripe.net"),
    (4 << 16, (4 << 16) + 65535, "whois.lacnic.net"),
    (5 << 16, (5 << 16) + 65535, "whois.afrinic.net"),
    (6 << 16, (6 << 16) + 65535, "whois.arin.net"),
    // 私有 ASN 段
    (4200000000, 4294967294, "whois.ripe.net"),
];

// ---------------------------------------------------------------------------
// IPv4 分配表（先匹配优先）：历史回收块 + 主表，原始文本嵌入。
// 格式与上游 ip_del_recovered.h / ip_del_list 完全一致（含注释），
// 启动时按 make_ip_del.pl 的规则解析。UNKNOWN→\x05，无点服务器补 whois./.net。
pub const IP4_RAW: &str = r##"
/* 45.4.0.0 - 45.7.255.255 */
{ 755236864, 4294705152, "whois.lacnic.net" },
/* 45.8.0.0 - 45.15.255.255 */
{ 755499008, 4294443008, "whois.ripe.net" },
/* 45.64.0.0 - 45.65.15.255 */
{ 759234560, 4294963200, "whois.apnic.net" },
{ 759169024, 4294901760, "whois.apnic.net" },
/* 45.65.16.0 - 45.65.63.255 */
{ 759238656, 4294963200, "whois.apnic.net" },
{ 759242752, 4294959104, "whois.apnic.net" },
/* 45.65.64.0 - 45.65.127.255 */
{ 759250944, 4294950912, "whois.ripe.net" },
/* 45.65.128.0 - 45.65.255.255 */
{ 759267328, 4294934528, "whois.lacnic.net" },
/* 45.66.0.0 - 45.67.255.255 */
{ 759300096, 4294836224, "whois.ripe.net" },
/* 45.68.0.0 - 45.71.255.255 */
{ 759431168, 4294705152, "whois.lacnic.net" },
/* 45.80.0.0 - 45.95.255.255 */
{ 760217600, 4293918720, "whois.ripe.net" },
/* 45.96.0.0 - 45.111.255.255 */
{ 761266176, 4293918720, "whois.afrinic.net" },
/* 45.112.0.0 - 45.127.255.255 */
{ 762314752, 4293918720, "whois.apnic.net" },
/* 45.128.0.0 - 45.159.255.255 */
{ 763363328, 4292870144, "whois.ripe.net" },
/* 45.160.0.0 - 45.191.255.255 */
{ 765460480, 4292870144, "whois.lacnic.net" },
/* 45.192.0.0 - 45.222.255.255 */
{ 767557632, 4293918720, "whois.afrinic.net" },
{ 768606208, 4294443008, "whois.afrinic.net" },
{ 769130496, 4294705152, "whois.afrinic.net" },
{ 769392640, 4294836224, "whois.afrinic.net" },
{ 769523712, 4294901760, "whois.afrinic.net" },
/* 45.224.0.0 - 45.239.255.255 */
{ 769654784, 4293918720, "whois.lacnic.net" },
/* 45.240.0.0 - 45.247.255.255 */
{ 770703360, 4294443008, "whois.afrinic.net" },
/* 45.248.0.0 - 45.255.255.255 */
{ 771227648, 4294443008, "whois.apnic.net" },
/* 66.251.128.0 - 66.251.191.255 */
{ 1123778560, 4294950912, "whois.afrinic.net" },
/* 72.44.16.0 - 72.44.31.255 */
{ 1210847232, 4294963200, "whois.lacnic.net" },
/* 128.201.0.0 - 128.201.255.255 */
{ 2160656384, 4294901760, "whois.lacnic.net" },
/* 131.196.0.0 - 131.196.255.255 */
{ 2210660352, 4294901760, "whois.lacnic.net" },
/* 137.59.0.0 - 137.59.255.255 */
{ 2302345216, 4294901760, "whois.apnic.net" },
/* 139.5.0.0 - 139.5.255.255 */
{ 2332360704, 4294901760, "whois.apnic.net" },
/* 139.26.0.0 - 139.26.255.255 */
{ 2333736960, 4294901760, "whois.afrinic.net" },
/* 144.48.0.0 - 144.48.255.255 */
{ 2419064832, 4294901760, "whois.apnic.net" },
/* 146.196.32.0 - 146.196.127.255 */
{ 2462326784, 4294959104, "whois.apnic.net" },
{ 2462334976, 4294950912, "whois.apnic.net" },
/* 146.196.128.0 - 146.196.255.255 */
{ 2462351360, 4294934528, "whois.afrinic.net" },
/* 147.78.0.0 - 147.78.255.255 */
{ 2471362560, 4294901760, "whois.ripe.net" },
/* 149.248.0.0 - 149.248.255.255 */
{ 2516058112, 4294901760, "whois.arin.net" },
/* 152.89.0.0 - 152.89.255.255 */
{ 2555969536, 4294901760, "whois.ripe.net" },
/* 157.119.0.0 - 157.119.255.255 */
{ 2641821696, 4294901760, "whois.apnic.net" },
/* 160.19.20.0 - 160.19.23.255 */
{ 2685604864, 4294966272, "whois.apnic.net" },
/* 160.19.36.0 - 160.19.39.255 */
{ 2685608960, 4294966272, "whois.afrinic.net" },
/* 160.19.44.0 - 160.19.47.255 */
{ 2685611008, 4294966272, "whois.lacnic.net" },
/* 160.19.48.0 - 160.19.55.255 */
{ 2685612032, 4294965248, "whois.apnic.net" },
/* 160.19.60.0 - 160.19.63.255 */
{ 2685615104, 4294966272, "whois.afrinic.net" },
/* 160.19.64.0 - 160.19.67.255 */
{ 2685616128, 4294966272, "whois.apnic.net" },
/* 160.19.92.0 - 160.19.95.255 */
{ 2685623296, 4294966272, "whois.ripe.net" },
/* 160.19.96.0 - 160.19.103.255 */
{ 2685624320, 4294965248, "whois.afrinic.net" },
/* 160.19.112.0 - 160.19.143.255 */
{ 2685628416, 4294963200, "whois.afrinic.net" },
{ 2685632512, 4294963200, "whois.afrinic.net" },
/* 160.19.152.0 - 160.19.155.255 */
{ 2685638656, 4294966272, "whois.afrinic.net" },
/* 160.19.168.0 - 160.19.175.255 */
{ 2685642752, 4294965248, "whois.lacnic.net" },
/* 160.19.180.0 - 160.19.183.255 */
{ 2685645824, 4294966272, "whois.ripe.net" },
/* 160.19.188.0 - 160.19.191.255 */
{ 2685647872, 4294966272, "whois.afrinic.net" },
/* 160.19.192.0 - 160.19.199.255 */
{ 2685648896, 4294965248, "whois.afrinic.net" },
/* 160.19.200.0 - 160.19.203.255 */
{ 2685650944, 4294966272, "whois.lacnic.net" },
/* 160.19.208.0 - 160.19.223.255 */
{ 2685652992, 4294963200, "whois.apnic.net" },
/* 160.19.224.0 - 160.19.227.255 */
{ 2685657088, 4294966272, "whois.apnic.net" },
/* 160.19.232.0 - 160.19.239.255 */
{ 2685659136, 4294965248, "whois.afrinic.net" },
/* 160.19.240.0 - 160.19.255.255 */
{ 2685661184, 4294963200, "whois.lacnic.net" },
/* 160.20.0.0 - 160.20.15.255 */
{ 2685665280, 4294963200, "whois.apnic.net" },
/* 160.20.20.0 - 160.20.23.255 */
{ 2685670400, 4294966272, "whois.lacnic.net" },
/* 160.20.24.0 - 160.20.31.255 */
{ 2685671424, 4294965248, "whois.afrinic.net" },
/* 160.20.32.0 - 160.20.35.255 */
{ 2685673472, 4294966272, "whois.lacnic.net" },
/* 160.20.40.0 - 160.20.47.255 */
{ 2685675520, 4294965248, "whois.apnic.net" },
/* 160.20.48.0 - 160.20.63.255 */
{ 2685677568, 4294963200, "whois.apnic.net" },
/* 160.20.64.0 - 160.20.71.255 */
{ 2685681664, 4294965248, "whois.lacnic.net" },
/* 160.20.72.0 - 160.20.75.255 */
{ 2685683712, 4294966272, "whois.apnic.net" },
/* 160.20.80.0 - 160.20.95.255 */
{ 2685685760, 4294963200, "whois.lacnic.net" },
/* 160.20.96.0 - 160.20.103.255 */
{ 2685689856, 4294965248, "whois.ripe.net" },
/* 160.20.108.0 - 160.20.111.255 */
{ 2685692928, 4294966272, "whois.ripe.net" },
/* 160.20.112.0 - 160.20.115.255 */
{ 2685693952, 4294966272, "whois.afrinic.net" },
/* 160.20.144.0 - 160.20.159.255 */
{ 2685702144, 4294963200, "whois.ripe.net" },
/* 160.20.160.0 - 160.20.207.255 */
{ 2685706240, 4294959104, "whois.lacnic.net" },
{ 2685714432, 4294963200, "whois.lacnic.net" },
/* 160.20.213.0 - 160.20.213.255 */
{ 2685719808, 4294967040, "whois.afrinic.net" },
/* 160.20.214.0 - 160.20.215.255 */
{ 2685720064, 4294966784, "whois.ripe.net" },
/* 160.20.217.0 - 160.20.217.255 */
{ 2685720832, 4294967040, "whois.afrinic.net" },
/* 160.20.218.0 - 160.20.219.255 */
{ 2685721088, 4294966784, "whois.lacnic.net" },
/* 160.20.221.0 - 160.20.221.255 */
{ 2685721856, 4294967040, "whois.afrinic.net" },
/* 160.20.222.0 - 160.20.223.255 */
{ 2685722112, 4294966784, "whois.apnic.net" },
/* 160.20.225.0 - 160.20.225.255 */
{ 2685722880, 4294967040, "whois.lacnic.net" },
/* 160.20.226.0 - 160.20.227.255 */
{ 2685723136, 4294966784, "whois.afrinic.net" },
/* 160.20.229.0 - 160.20.229.255 */
{ 2685723904, 4294967040, "whois.ripe.net" },
/* 160.20.242.0 - 160.20.243.255 */
{ 2685727232, 4294966784, "whois.lacnic.net" },
/* 160.20.246.0 - 160.20.247.255 */
{ 2685728256, 4294966784, "whois.lacnic.net" },
/* 160.20.248.0 - 160.20.249.255 */
{ 2685728768, 4294966784, "whois.ripe.net" },
/* 160.20.252.0 - 160.20.255.255 */
{ 2685729792, 4294966272, "whois.afrinic.net" },
/* 160.202.8.0 - 160.202.15.255 */
{ 2697594880, 4294965248, "whois.apnic.net" },
/* 160.202.16.0 - 160.202.31.255 */
{ 2697596928, 4294963200, "whois.ripe.net" },
/* 160.202.32.0 - 160.202.63.255 */
{ 2697601024, 4294959104, "whois.apnic.net" },
/* 160.202.128.0 - 160.202.255.255 */
{ 2697625600, 4294934528, "whois.apnic.net" },
/* 160.238.0.0 - 160.238.0.255 */
{ 2699952128, 4294967040, "whois.apnic.net" },
/* 160.238.11.0 - 160.238.11.255 */
{ 2699954944, 4294967040, "whois.afrinic.net" },
/* 160.238.12.0 - 160.238.19.255 */
{ 2699955200, 4294966272, "whois.apnic.net" },
{ 2699956224, 4294966272, "whois.apnic.net" },
/* 160.238.21.0 - 160.238.21.255 */
{ 2699957504, 4294967040, "whois.ripe.net" },
/* 160.238.24.0 - 160.238.29.255 */
{ 2699958272, 4294966272, "whois.lacnic.net" },
{ 2699959296, 4294966784, "whois.lacnic.net" },
/* 160.238.33.0 - 160.238.33.255 */
{ 2699960576, 4294967040, "whois.apnic.net" },
/* 160.238.34.0 - 160.238.35.255 */
{ 2699960832, 4294966784, "whois.apnic.net" },
/* 160.238.36.0 - 160.238.39.255 */
{ 2699961344, 4294966272, "whois.ripe.net" },
/* 160.238.48.0 - 160.238.49.255 */
{ 2699964416, 4294966784, "whois.afrinic.net" },
/* 160.238.50.0 - 160.238.50.255 */
{ 2699964928, 4294967040, "whois.afrinic.net" },
/* 160.238.52.0 - 160.238.55.255 */
{ 2699965440, 4294966272, "whois.ripe.net" },
/* 160.238.57.0 - 160.238.57.255 */
{ 2699966720, 4294967040, "whois.afrinic.net" },
/* 160.238.58.0 - 160.238.59.255 */
{ 2699966976, 4294966784, "whois.apnic.net" },
/* 160.238.60.0 - 160.238.61.255 */
{ 2699967488, 4294966784, "whois.ripe.net" },
/* 160.238.63.0 - 160.238.63.255 */
{ 2699968256, 4294967040, "whois.lacnic.net" },
/* 160.238.64.0 - 160.238.95.255 */
{ 2699968512, 4294959104, "whois.apnic.net" },
/* 160.238.96.0 - 160.238.99.255 */
{ 2699976704, 4294966272, "whois.ripe.net" },
/* 160.238.101.0 - 160.238.101.255 */
{ 2699977984, 4294967040, "whois.afrinic.net" },
/* 160.238.104.0 - 160.238.111.255 */
{ 2699978752, 4294965248, "whois.lacnic.net" },
/* 160.238.112.0 - 160.238.127.255 */
{ 2699980800, 4294963200, "whois.ripe.net" },
/* 160.238.128.0 - 160.238.255.255 */
{ 2699984896, 4294934528, "whois.lacnic.net" },
/* 161.123.0.0 - 161.123.255.255 */
{ 2709192704, 4294901760, "whois.afrinic.net" },
/* 162.12.196.0 - 162.12.199.255 */
{ 2718745600, 4294966272, "whois.lacnic.net" },
/* 162.12.200.0 - 162.12.207.255 */
{ 2718746624, 4294965248, "whois.ripe.net" },
/* 162.12.208.0 - 162.12.215.255 */
{ 2718748672, 4294965248, "whois.apnic.net" },
/* 162.12.240.0 - 162.12.247.255 */
{ 2718756864, 4294965248, "whois.apnic.net" },
/* 164.160.0.0 - 164.160.255.255 */
{ 2761949184, 4294901760, "whois.afrinic.net" },
/* 164.163.0.0 - 164.163.255.255 */
{ 2762145792, 4294901760, "whois.lacnic.net" },
/* 192.12.109.0 - 192.12.109.255 */
{ 3222039808, 4294967040, "whois.apnic.net" },
/* 192.12.110.0 - 192.12.111.255 */
{ 3222040064, 4294966784, "whois.afrinic.net" },
/* 192.12.112.0 - 192.12.115.255 */
{ 3222040576, 4294966272, "whois.lacnic.net" },
/* 192.12.116.0 - 192.12.117.255 */
{ 3222041600, 4294966784, "whois.afrinic.net" },
/* 192.12.118.0 - 192.12.118.255 */
{ 3222042112, 4294967040, "whois.lacnic.net" },
/* 192.26.110.0 - 192.26.110.255 */
{ 3222957568, 4294967040, "whois.apnic.net" },
/* 192.42.65.0 - 192.42.65.255 */
{ 3223994624, 4294967040, "whois.ripe.net" },
/* 192.47.36.0 - 192.47.36.255 */
{ 3224314880, 4294967040, "whois.afrinic.net" },
/* 192.51.188.0 - 192.51.188.255 */
{ 3224615936, 4294967040, "whois.apnic.net" },
/* 192.51.240.0 - 192.51.240.255 */
{ 3224629248, 4294967040, "whois.afrinic.net" },
/* 192.54.244.0 - 192.54.244.255 */
{ 3224826880, 4294967040, "whois.ripe.net" },
/* 192.67.23.0 - 192.67.23.255 */
{ 3225622272, 4294967040, "whois.lacnic.net" },
/* 192.68.185.0 - 192.68.185.255 */
{ 3225729280, 4294967040, "whois.lacnic.net" },
/* 192.70.192.0 - 192.70.199.255 */
{ 3225862144, 4294965248, "whois.ripe.net" },
/* 192.70.200.0 - 192.70.201.255 */
{ 3225864192, 4294966784, "whois.afrinic.net" },
/* 192.75.4.0 - 192.75.4.255 */
{ 3226141696, 4294967040, "whois.lacnic.net" },
/* 192.75.137.0 - 192.75.137.255 */
{ 3226175744, 4294967040, "whois.apnic.net" },
/* 192.75.236.0 - 192.75.236.255 */
{ 3226201088, 4294967040, "whois.afrinic.net" },
/* 192.83.207.0 - 192.83.207.255 */
{ 3226717952, 4294967040, "whois.lacnic.net" },
/* 192.83.208.0 - 192.83.215.255 */
{ 3226718208, 4294965248, "whois.afrinic.net" },
/* 192.83.216.0 - 192.83.216.255 */
{ 3226720256, 4294967040, "whois.ripe.net" },
/* 192.91.200.0 - 192.91.200.255 */
{ 3227240448, 4294967040, "whois.afrinic.net" },
/* 192.91.254.0 - 192.91.254.255 */
{ 3227254272, 4294967040, "whois.lacnic.net" },
/* 192.92.154.0 - 192.92.154.255 */
{ 3227294208, 4294967040, "whois.lacnic.net" },
/* 192.94.78.0 - 192.94.78.255 */
{ 3227405824, 4294967040, "whois.ripe.net" },
/* 192.135.90.0 - 192.135.91.255 */
{ 3230095872, 4294966784, "whois.apnic.net" },
/* 192.135.95.0 - 192.135.95.255 */
{ 3230097152, 4294967040, "whois.lacnic.net" },
/* 192.135.99.0 - 192.135.99.255 */
{ 3230098176, 4294967040, "whois.apnic.net" },
/* 192.135.100.0 - 192.135.100.255 */
{ 3230098432, 4294967040, "whois.ripe.net" },
/* 192.135.185.0 - 192.135.185.255 */
{ 3230120192, 4294967040, "whois.lacnic.net" },
/* 192.140.1.0 - 192.140.1.255 */
{ 3230400768, 4294967040, "whois.lacnic.net" },
/* 192.140.2.0 - 192.140.3.255 */
{ 3230401024, 4294966784, "whois.ripe.net" },
/* 192.140.8.0 - 192.140.15.255 */
{ 3230402560, 4294965248, "whois.lacnic.net" },
/* 192.140.16.0 - 192.140.127.255 */
{ 3230404608, 4294963200, "whois.lacnic.net" },
{ 3230408704, 4294959104, "whois.lacnic.net" },
{ 3230416896, 4294950912, "whois.lacnic.net" },
/* 192.140.128.0 - 192.140.255.255 */
{ 3230433280, 4294934528, "whois.apnic.net" },
/* 192.141.0.0 - 192.141.255.255 */
{ 3230466048, 4294901760, "whois.lacnic.net" },
/* 192.142.0.0 - 192.143.255.255 */
{ 3230531584, 4294836224, "whois.afrinic.net" },
/* 192.144.0.0 - 192.144.63.255 */
{ 3230662656, 4294950912, "whois.ripe.net" },
/* 192.144.64.0 - 192.144.71.255 */
{ 3230679040, 4294965248, "whois.lacnic.net" },
/* 192.144.72.0 - 192.144.73.255 */
{ 3230681088, 4294966784, "whois.lacnic.net" },
/* 192.144.75.0 - 192.144.75.255 */
{ 3230681856, 4294967040, "whois.ripe.net" },
/* 192.144.78.0 - 192.144.79.255 */
{ 3230682624, 4294966784, "whois.apnic.net" },
/* 192.144.80.0 - 192.144.95.255 */
{ 3230683136, 4294963200, "whois.apnic.net" },
/* 192.144.96.0 - 192.144.127.255 */
{ 3230687232, 4294959104, "whois.lacnic.net" },
/* 192.145.0.0 - 192.145.127.255 */
{ 3230728192, 4294934528, "whois.ripe.net" },
/* 192.145.128.0 - 192.145.191.255 */
{ 3230760960, 4294950912, "whois.afrinic.net" },
/* 192.145.192.0 - 192.145.223.255 */
{ 3230777344, 4294959104, "whois.lacnic.net" },
/* 192.145.224.0 - 192.145.227.255 */
{ 3230785536, 4294966272, "whois.ripe.net" },
/* 192.145.228.0 - 192.145.229.255 */
{ 3230786560, 4294966784, "whois.apnic.net" },
/* 192.145.230.0 - 192.145.230.255 */
{ 3230787072, 4294967040, "whois.afrinic.net" },
/* 192.153.12.0 - 192.153.12.255 */
{ 3231255552, 4294967040, "whois.lacnic.net" },
/* 192.156.144.0 - 192.156.144.255 */
{ 3231485952, 4294967040, "whois.apnic.net" },
/* 192.156.220.0 - 192.156.220.255 */
{ 3231505408, 4294967040, "whois.apnic.net" },
/* 192.172.232.0 - 192.172.232.255 */
{ 3232557056, 4294967040, "whois.ripe.net" },
/* 192.188.82.0 - 192.188.83.255 */
{ 3233567232, 4294966784, "whois.apnic.net" },
/* 192.188.248.0 - 192.188.248.255 */
{ 3233609728, 4294967040, "whois.ripe.net" },
/* 192.197.113.0 - 192.197.113.255 */
{ 3234164992, 4294967040, "whois.apnic.net" },
/* 192.251.230.0 - 192.251.230.255 */
{ 3237733888, 4294967040, "whois.ripe.net" },
/* 198.97.38.0 - 198.97.38.255 */
{ 3328255488, 4294967040, "whois.lacnic.net" },
/* 199.21.172.0 - 199.21.175.255 */
{ 3340086272, 4294966272, "whois.apnic.net" },
/* 199.212.57.0 - 199.212.57.255 */
{ 3352574208, 4294967040, "whois.apnic.net" },
/* 204.8.204.0 - 204.8.207.255 */
{ 3423128576, 4294966272, "whois.afrinic.net" },
/* 204.11.0.0 - 204.11.3.255 */
{ 3423272960, 4294966272, "whois.ripe.net" },
/* 204.48.32.0 - 204.48.33.255 */
{ 3425705984, 4294966784, "whois.ripe.net" },
/* 204.52.191.0 - 204.52.191.255 */
{ 3426008832, 4294967040, "whois.apnic.net" },
/* 204.225.42.0 - 204.225.43.255 */
{ 3437308416, 4294966784, "whois.lacnic.net" },
/* 205.211.83.0 - 205.211.83.255 */
{ 3453178624, 4294967040, "whois.ripe.net" },
/* 208.85.156.0 - 208.85.159.255 */
{ 3495271424, 4294966272, "whois.afrinic.net" },
/* 216.98.208.0 - 216.98.223.255 */
{ 3630354432, 4294963200, "whois.lacnic.net" },
/* 216.250.96.0 - 216.250.111.255 */
{ 3640287232, 4294963200, "whois.apnic.net" },
##RECOVERED-END##
// 以下为 ip_del_list（CIDR 记法），按 make_ip_del.pl 规则解析
0.0.0.0/8	UNKNOWN
1.0.0.0/8	apnic
2.0.0.0/8	ripe
5.0.0.0/8	ripe
14.64.0.0/11	whois.nic.or.kr
14.0.0.0/8	apnic
24.132.0.0/14	ripe
27.176.0.0/13	whois.nic.or.kr
27.0.0.0/8	apnic
31.0.0.0/8	ripe
36.0.0.0/8	apnic
37.0.0.0/8	ripe
39.0.0.0/8	apnic
41.0.0.0/8	afrinic
42.32.0.0/12	whois.nic.or.kr
42.0.0.0/7	apnic
46.0.0.0/8	ripe
49.8.0.0/14	whois.nic.or.kr
49.0.0.0/8	apnic
51.0.0.0/8	ripe
59.0.0.0/11	whois.nic.or.kr
58.0.0.0/7	apnic
61.72.0.0/13	whois.nic.or.kr
61.80.0.0/14	whois.nic.or.kr
61.84.0.0/15	whois.nic.or.kr
61.112.0.0/12	whois.nic.ad.jp
61.192.0.0/12	whois.nic.ad.jp
61.208.0.0/13	whois.nic.ad.jp
60.0.0.0/7	apnic
62.0.0.0/8	ripe
77.0.0.0/8	ripe
78.0.0.0/7	ripe
80.0.0.0/4	ripe
101.0.0.0/8	apnic
102.0.0.0/8	afrinic
103.0.0.0/8	apnic
105.0.0.0/8	afrinic
106.0.0.0/8	apnic
109.0.0.0/8	ripe
110.0.0.0/7	apnic
112.160.0.0/11	whois.nic.or.kr
115.0.0.0/12	whois.nic.or.kr
115.16.0.0/13	whois.nic.or.kr
118.32.0.0/11	whois.nic.or.kr
119.192.0.0/11	whois.nic.or.kr
112.0.0.0/5	apnic
121.128.0.0/10	whois.nic.or.kr
125.128.0.0/11	whois.nic.or.kr
120.0.0.0/6	apnic
124.0.0.0/7	apnic
126.0.0.0/8	apnic
0.0.0.0/1	arin
133.0.0.0/8	whois.nic.ad.jp
139.20.0.0/14	ripe
139.24.0.0/14	ripe
139.28.0.0/15	ripe
141.0.0.0/10	ripe
141.86.0.0/16	arin
141.64.0.0/11	ripe
141.96.0.0/14	ripe
141.100.0.0/16	ripe
145.0.0.0/8	ripe
146.48.0.0/16	ripe
149.202.0.0/15	ripe
149.204.0.0/16	ripe
149.206.0.0/15	ripe
149.208.0.0/12	ripe
149.224.0.0/12	ripe
149.240.0.0/13	ripe
149.248.0.0/14	ripe
150.183.0.0/16	whois.nic.or.kr
150.254.0.0/16	ripe
150.0.0.0/8	apnic
151.0.0.0/10	ripe
151.64.0.0/11	ripe
151.96.0.0/14	ripe
151.100.0.0/16	ripe
153.128.0.0/9	whois.nic.ad.jp
153.0.0.0/8	apnic
154.0.0.0/8	afrinic
155.232.0.0/13	afrinic
155.240.0.0/16	afrinic
160.216.0.0/14	ripe
160.220.0.0/16	ripe
160.44.0.0/14	ripe
160.48.0.0/12	ripe
160.115.0.0/16	afrinic
160.116.0.0/14	afrinic
160.120.0.0/14	afrinic
160.124.0.0/16	afrinic
163.156.0.0/14	ripe
163.160.0.0/12	ripe
163.195.0.0/16	afrinic
163.196.0.0/14	afrinic
163.200.0.0/14	afrinic
163.0.0.0/8	apnic
164.0.0.0/11	ripe
164.32.0.0/13	ripe
164.40.0.0/16	ripe
164.128.0.0/12	ripe
164.146.0.0/15	afrinic
164.148.0.0/14	afrinic
165.143.0.0/16	afrinic
165.144.0.0/14	afrinic
165.148.0.0/15	afrinic
169.208.0.0/12	apnic
171.16.0.0/12	ripe
171.32.0.0/15	ripe
171.0.0.0/8	apnic
175.192.0.0/10	whois.nic.or.kr
175.0.0.0/8	apnic
176.0.0.0/8	ripe
177.0.0.0/8	lacnic
178.0.0.0/8	ripe
179.0.0.0/8	lacnic
180.0.0.0/8	apnic
181.0.0.0/8	lacnic
183.96.0.0/11	whois.nic.or.kr
182.0.0.0/7	apnic
185.0.0.0/8	ripe
186.0.0.0/7	lacnic
188.0.0.0/8	ripe
189.0.0.0/8	lacnic
190.0.0.0/7	lacnic
128.0.0.0/2	arin
192.71.0.0/16	ripe
192.72.253.0/24	arin
192.72.254.0/24	arin
192.72.0.0/16	apnic
192.106.0.0/16	ripe
192.114.0.0/15	ripe
192.116.0.0/15	ripe
192.118.0.0/16	ripe
192.162.0.0/16	ripe
192.164.0.0/14	ripe
192.0.0.0/8	arin
193.0.0.0/8	ripe
194.0.0.0/7	ripe
196.0.0.0/7	afrinic
198.0.0.0/7	arin
200.0.0.0/7	lacnic
202.11.0.0/16	whois.nic.ad.jp
202.13.0.0/16	whois.nic.ad.jp
202.15.0.0/16	whois.nic.ad.jp
202.16.0.0/14	whois.nic.ad.jp
202.20.128.0/17	whois.nic.or.kr
202.23.0.0/16	whois.nic.ad.jp
202.24.0.0/15	whois.nic.ad.jp
202.26.0.0/16	whois.nic.ad.jp
202.30.0.0/15	whois.nic.or.kr
202.32.0.0/14	whois.nic.ad.jp
202.48.0.0/16	whois.nic.ad.jp
202.39.128.0/17	twnic
202.208.0.0/12	whois.nic.ad.jp
202.224.0.0/11	whois.nic.ad.jp
203.0.0.0/10	apnic
203.66.0.0/16	twnic
203.69.0.0/16	twnic
203.74.0.0/15	twnic
203.136.0.0/14	whois.nic.ad.jp
203.140.0.0/15	whois.nic.ad.jp
203.178.0.0/15	whois.nic.ad.jp
203.180.0.0/14	whois.nic.ad.jp
203.224.0.0/11	whois.nic.or.kr
202.0.0.0/7	apnic
204.0.0.0/14	rwhois.gin.ntt.net
204.0.0.0/6	arin
208.0.0.0/7	arin
209.94.192.0/19	lacnic
210.59.128.0/17	twnic
210.61.0.0/16	twnic
210.62.252.0/22	twnic
210.65.0.0/16	twnic
210.71.128.0/17	twnic
210.90.0.0/15	whois.nic.or.kr
210.92.0.0/14	whois.nic.or.kr
210.96.0.0/11	whois.nic.or.kr
210.128.0.0/11	whois.nic.ad.jp
210.160.0.0/12	whois.nic.ad.jp
210.178.0.0/15	whois.nic.or.kr
210.180.0.0/14	whois.nic.or.kr
210.188.0.0/14	whois.nic.ad.jp
210.196.0.0/14	whois.nic.ad.jp
210.204.0.0/14	whois.nic.or.kr
210.216.0.0/13	whois.nic.or.kr
210.224.0.0/12	whois.nic.ad.jp
210.240.0.0/16	twnic
210.241.0.0/18	twnic
210.241.224.0/19	twnic
210.242.0.0/15	twnic
210.248.0.0/13	whois.nic.ad.jp
211.0.0.0/12	whois.nic.ad.jp
211.16.0.0/14	whois.nic.ad.jp
211.20.0.0/15	twnic
211.22.0.0/16	twnic
211.32.0.0/11	whois.nic.or.kr
211.75.0.0/16	twnic
211.72.0.0/16	twnic
211.104.0.0/13	whois.nic.or.kr
211.112.0.0/13	whois.nic.or.kr
211.120.0.0/13	whois.nic.ad.jp
211.128.0.0/13	whois.nic.ad.jp
211.168.0.0/13	whois.nic.or.kr
211.176.0.0/12	whois.nic.or.kr
211.192.0.0/10	whois.nic.or.kr
210.0.0.0/7	apnic
213.154.32.0/19	afrinic
213.154.64.0/19	afrinic
212.0.0.0/7	ripe
214.0.0.0/7	arin
216.0.0.0/8	arin
217.0.0.0/8	ripe
218.36.0.0/14	whois.nic.or.kr
218.40.0.0/13	whois.nic.ad.jp
218.48.0.0/13	whois.nic.or.kr
219.96.0.0/11	whois.nic.ad.jp
218.144.0.0/12	whois.nic.or.kr
218.160.0.0/12	twnic
218.216.0.0/13	whois.nic.ad.jp
218.224.0.0/13	whois.nic.ad.jp
218.232.0.0/13	whois.nic.or.kr
219.240.0.0/15	whois.nic.or.kr
219.248.0.0/13	whois.nic.or.kr
218.0.0.0/7	apnic
220.64.0.0/11	whois.nic.or.kr
220.96.0.0/14	whois.nic.ad.jp
220.103.0.0/16	whois.nic.or.kr
220.104.0.0/13	whois.nic.ad.jp
220.149.0.0/16	whois.nic.or.kr
221.138.0.0/15	whois.nic.or.kr
221.140.0.0/14	whois.nic.or.kr
221.144.0.0/12	whois.nic.or.kr
221.160.0.0/13	whois.nic.or.kr
222.96.0.0/12	whois.nic.or.kr
222.112.0.0/13	whois.nic.or.kr
222.120.0.0/15	whois.nic.or.kr
222.122.0.0/16	whois.nic.or.kr
222.232.0.0/13	whois.nic.or.kr
220.0.0.0/6	apnic
"##;

// ---------------------------------------------------------------------------
// 新 gTLD 列表（new_gtlds_list）：命中后使用 whois.nic.<tld>。
pub const NEW_GTLDS_RAW: &str = r##"
aaa aarp abb abbott abbvie abc able abogado abudhabi academy accenture
accountant accountants aco actor ads adult aeg aetna afl africa agakhan
agency aig airbus airforce airtel akdn alibaba alipay allfinanz allstate ally
alsace alstom amazon americanexpress americanfamily amex amfam amica
amsterdam analytics android anquan aol apartments app apple aquarelle arab
aramco archi army art arte asda associates athleta attorney auction audi
audible audio auspost author auto autos aws axa azure baby baidu banamex band
bank bar barcelona barclaycard barclays barefoot bargains baseball basketball
bauhaus bayern bbc bbt bbva bcg bcn beats beauty beer berlin best bestbuy bet
bharti bible bid bike bing bingo bio black blackfriday blockbuster blog
bloomberg blue bms bmw bnpparibas boats boehringer bofa bom bond boo book
booking bosch bostik boston bot boutique box bradesco bridgestone broadway
broker brother brussels build builders business buy buzz bzh cab cafe cal
call calvinklein cam camera camp canon capetown capital capitalone car
caravan cards care career careers cars casa case cash casino catering
catholic cba cbn cbre center ceo cern cfa cfd chanel channel charity chase
chat cheap chintai christmas chrome church cipriani circle cisco citadel citi
citic city claims cleaning click clinic clinique clothing cloud club clubmed
coach codes coffee college cologne commbank community company compare
computer comsec condos construction consulting contact contractors cooking
cool corsica country coupon coupons courses cpa credit creditcard
creditunion cricket crown crs cruise cruises cuisinella cymru cyou dad dance
data date dating datsun day dclk dds deal dealer deals degree delivery dell
deloitte delta democrat dental dentist desi design dev dhl diamonds diet
digital direct directory discount discover dish diy dnp docs doctor dog
domains dot download drive dtv dubai dupont durban dvag dvr earth eat eco
edeka education email emerck energy engineer engineering enterprises epson
equipment ericsson erni esq estate eurovision eus events exchange expert
exposed express extraspace fage fail fairwinds faith family fan fans farm
farmers fashion fast fedex feedback ferrari ferrero fidelity fido film final
finance financial fire firestone firmdale fish fishing fit fitness flickr
flights flir florist flowers fly foo food football ford forex forsale forum
foundation fox free fresenius frl frogans frontier ftr fujitsu fun fund
furniture futbol fyi gal gallery gallo gallup game games gap garden gay gbiz
gdn gea gent genting george ggee gift gifts gives giving glass gle global
globo gmail gmbh gmo gmx godaddy gold goldpoint golf goodyear goog google gop
got grainger graphics gratis green gripe grocery group gucci guge guide
guitars guru hair hamburg hangout haus hbo hdfc hdfcbank health healthcare
help helsinki here hermes hiphop hisamitsu hitachi hiv hkt hockey holdings
holiday homedepot homegoods homes homesense honda horse hospital host hosting
hot hotels hotmail house how hsbc hughes hyatt hyundai ibm icbc ice icu ieee
ifm ikano imamat imdb immo immobilien inc industries infiniti ing ink
institute insurance insure international intuit investments ipiranga irish
ismaili ist istanbul itau itv jaguar java jcb jeep jetzt jewelry jio jll jmp
jnj joburg jot joy jpmorgan jprs juegos juniper kaufen kddi kerryhotels
kerryproperties kfh kia kids kim kindle kitchen kiwi koeln komatsu kosher kpmg
kpn krd kred kuokgroup kyoto lacaixa lamborghini lamer land landrover lanxess
lasalle lat latino latrobe law lawyer lds lease leclerc lefrak legal lego
lexus lgbt lidl life lifeinsurance lifestyle lighting like lilly limited limo
lincoln link live living llc llp loan loans locker locus lol london lotte
lotto love lpl lplfinancial ltd ltda lundbeck luxe luxury madrid maif maison
makeup man management mango map market marketing markets marriott marshalls
mattel mba mckinsey med media meet melbourne meme memorial men menu merckmsd
miami microsoft mini mint mit mitsubishi mlb mls mma mobile moda moe moi mom
monash money monster mormon mortgage moscow moto motorcycles mov movie msd
mtn mtr music nab nagoya navy nba nec netbank netflix network neustar new news
next nextdirect nexus nfl ngo nhk nico nike nikon ninja nissan nissay nokia
norton now nowruz nowtv nra nrw ntt nyc obi observer office okinawa olayan
olayangroup ollo omega one ong onl online ooo open oracle orange organic
origins osaka otsuka ott ovh page panasonic paris pars partners parts party
pay pccw pet pfizer pharmacy phd philips phone photo photography photos physio
pics pictet pictures pid pin ping pink pioneer pizza place play playstation
plumbing plus pnc pohl poker politie porn praxi press prime prod productions
prof progressive promo properties property protection pru prudential pub pwc
qpon quebec quest racing radio read realestate realtor realty recipes red
redumbrella rehab reise reisen reit reliance ren rent rentals repair report
republican rest restaurant review reviews rexroth rich richardli ricoh ril
rio rip rocks rodeo rogers room rsvp rugby ruhr run rwe ryukyu saarland safe
safety sakura sale salon samsclub samsung sandvik sandvikcoromant sanofi sap
sarl sas save saxo sbi sbs scb schaeffler schmidt scholarships school schule
schwarz science scot search seat secure security seek select sener services
seven sew sex sexy sfr shangrila sharp shell shia shiksha shoes shop shopping
shouji show silk sina singles site ski skin sky skype sling smart smile sncf
soccer social softbank software sohu solar solutions song sony soy spa space
sport spot srl stada staples star statebank statefarm stc stcgroup stockholm
storage store stream studio study style sucks supplies supply support surf
surgery suzuki swatch swiss sydney systems tab taipei talk taobao target
tatamotors tatar tattoo tax taxi tci tdk team tech technology temasek tennis
teva thd theater theatre tiaa tickets tienda tips tires tirol tjmaxx tjx
tkmaxx tmall today tokyo tools top toray toshiba total tours town toyota toys
trade trading training travelers travelersinsurance trust trv tube tui tunes
tushu tvs ubank ubs unicom university uno uol ups vacations vana vanguard
vegas ventures verisign versicherung vet viajes video vig viking villas vin
vip virgin visa vision viva vivo vlaanderen vodka volvo vote voting voto
voyage wales walmart walter wang wanggou watch watches weather weatherchannel
webcam weber website wed wedding weibo weir whoswho wien wiki williamhill win
windows wine winners wme woodside work works world wow wtc wtf xbox xerox
xihuan xin xn--11b4c3d xn--1ck2e1b xn--1qqw23a xn--30rr7y xn--3bst00m
xn--3ds443g xn--3pxu8k xn--42c2d9a xn--45q11c xn--4gbrim xn--55qw42g
xn--55qx5d xn--5su34j936bgsg xn--5tzm5g xn--6frz82g xn--6qq986b3xl
xn--80adxhks xn--80aqecdr1a xn--80asehdb xn--80aswg xn--8y0a063a xn--9dbq2a
xn--9et52u xn--9krt00a xn--b4w605ferd xn--bck1b9a5dre4c xn--c1avg xn--c2br7g
xn--cck2b3b xn--cckwcxetd xn--cg4bki xn--czr694b xn--czrs0t xn--czru2d
xn--d1acj3b xn--eckvdtc9d xn--efvy88h xn--fct429k xn--fhbei xn--fiq228c5hs
xn--fiq64b xn--fjq720a xn--flw351e xn--fzys8d69uvgm xn--g2xx48c xn--gckr3f0f
xn--gk3at1e xn--hxt814e xn--i1b6b1a6a2e xn--imr513n xn--io0a7i xn--j1aef
xn--jlq480n2rg xn--jvr189m xn--kcrx77d1x4a xn--kput3i xn--mgba3a3ejt
xn--mgba7c0bbn0a xn--mgbab2bd xn--mgbca7dzdo xn--mgbi4ecexp xn--mgbt3dhd
xn--mk1bu44c xn--mxtq1m xn--ngbc5azd xn--ngbe9e0a xn--ngbrx xn--nqv7f
xn--nqv7fs00ema xn--nyqy26a xn--otu796d xn--p1acf xn--pssy2u xn--q9jyb4c
xn--qcka1pmc xn--rhqv96g xn--rovu88b xn--ses554g xn--t60b56a xn--tckwe
xn--tiq49xqyj xn--unup4y xn--vermgensberater-ctb xn--vermgensberatung-pwb
xn--vhquv xn--vuq861b xn--w4r85el8fhu5dnra xn--w4rs40l xn--xhq521b
xn--zfr164b xyz yachts yahoo yamaxun yandex yodobashi yoga yokohama you
youtube yun zappos zara zero zip zone zuerich
"##;

// ---------------------------------------------------------------------------
// 免责声明隐藏表（-H）：(起始句, 结束句)；结束句为空串表示遇到空行停止；
// 结束句为 None 表示隐藏到输出末尾。
pub const HIDE_STRINGS: &[(&str, Option<&str>)] = &[
    ("The data in Networksolutions.com's WHOIS database", None),
    ("TERMS OF USE: You are not authorized", None),
    ("The data in Register.com's WHOIS database", None),
    ("The Data in the Tucows Registrar WHOIS database", None),
    ("TERMS OF USE: The Data in Gabia' WHOIS", None),
    ("The data contained in GoDaddy.com", None),
    ("Personal data access and use are governed by French", None),
    ("The data in this whois database is provided to you", None),
    ("Please register your domains at; http://www.", None),
    ("%% NOTICE: Access to this information is provided", None),
    ("NOTICE: Access to the domain name's information", None),
    ("The data in MarkMonitor’s WHOIS", None),
    ("Corporation Service Company(c) (CSC)  The Trusted Partner", Some("Register your domain name at")),
    ("The data in Networksolutions.com's", None),
    ("# Welcome to the OVH WHOIS Server", Some("")),
    ("TERMS OF USE OF MELBOURNE IT WHOIS DATABASE", None),
    ("The data contained in this Registrar's Whois", None),
    ("The data in the FastDomain Inc. WHOIS database", None),
    ("Access to WHOIS information is provided", None),
    ("This Registry database contains ONLY .EDU", Some("domain names.")),
    ("Access to AFILIAS WHOIS information is provided", None),
    ("Access to Public Interest Registry WHOIS information", None),
    ("Telnames Limited, the Registry Operator for", None),
    ("Tralliance, Inc., the Registry Operator for .travel", None),
    ("The data in this record is provided by", None),
    ("Terms of Use: Donuts Inc. provides", None),
    ("TERMS OF USE: You  are  not  authorized", None),
    ("The Whois and RDAP services are provided by CentralNic", Some("")),
    (".Club Domains, LLC, the Registry Operator", None),
    ("% Except for agreed Internet operational purposes", None),
    ("TERMS OF USE: The information in the Whois database", None),
    ("The WHOIS service offered by Neustar, Inc, on behalf", None),
    ("The WHOIS service offered by the Registry Operator", None),
    ("Access to CCTLD WHOIS information is provided", Some("")),
    ("This WHOIS information is provided", None),
    ("% The WHOIS service offered by DNS Belgium", Some("")),
    (".CO Internet, S.A.S., the Administrator", None),
    ("%  *The information provided", Some("% https://www.nic.cr/iniciar-sesion/?next=/mi-cuenta/")),
    ("% The WHOIS service offered by EURid", Some("% of the database")),
    ("Access to .IN WHOIS information", None),
    ("access to .in whois information", None),
    ("% Use of CIRA's WHOIS service is governed by the Terms of Use in its Legal", None),
    ("Terms of Use: Access to WHOIS information", None),
    ("The Service is provided so that you may look", Some("We may discontinue")),
    ("NeuStar, Inc., the Registry Administrator for .US", None),
    ("; This data is provided ", None),
];

/// 服务器 → (字符集, 附加查询参数)。输出按字符集转码为 UTF-8。
pub const SERVERS_CHARSET: &[(&str, &str, &str)] = &[
    ("whois.afrinic.net", "utf-8", ""),
    ("whois.apnic.net", "iso-8859-1", ""),
    ("whois.cat", "utf-8", "-C UTF-8"),
    ("whois.conac.cn", "utf-8", ""),
    ("whois.corenic.net", "utf-8", "-C UTF-8"),
    ("whois.online.rs.corenic.net", "utf-8", "-C UTF-8"),
    ("whois.site.rs.corenic.net", "utf-8", "-C UTF-8"),
    ("whois.lacnic.net", "utf-8", ""),
    ("whois.museum", "utf-8", "-C UTF-8"),
    ("whois.ripe.net", "utf-8", "--charset UTF-8"),
    ("whois.nic.llyw.cymru", "utf-8", ""),
    ("whois.nic.gov.scot", "utf-8", ""),
    ("whois.nic.gov.wales", "utf-8", ""),
    ("whois.aeda.net.ae", "utf-8", ""),
    ("whois.nic.ar", "utf-8", ""),
    ("whois.ax", "utf-8", ""),
    ("whois.registro.br", "iso-8859-1", ""),
    ("whois.cira.ca", "utf-8", ""),
    ("whois.nic.ch", "utf-8", ""),
    ("whois.nic.cl", "utf-8", ""),
    ("whois.cnnic.cn", "utf-8", ""),
    ("whois.nic.cz", "utf-8", ""),
    ("whois.denic.de", "utf-8", ""),
    ("whois.enum.denic.de", "utf-8", ""),
    ("whois.dk-hostmaster.dk", "utf-8", "--charset=utf-8"),
    ("whois.punktum.dk", "utf-8", "--charset=utf-8"),
    ("whois.tld.ee", "utf-8", ""),
    ("whois.eu", "utf-8", ""),
    ("whois.fi", "iso-8859-1", ""),
    ("whois.nic.fo", "utf-8", ""),
    ("whois.nic.fr", "utf-8", ""),
    ("whois.hkirc.hk", "utf-8", ""),
    ("whois.nic.hr", "utf-8", ""),
    ("whois.nic.hu", "iso-8859-1", ""),
    ("whois.nic.ir", "utf-8", ""),
    ("whois.isnic.is", "iso-8859-1", ""),
    ("whois.nic.it", "utf-8", ""),
    ("whois.jprs.jp", "utf-8", ""),
    ("whois.nic.ad.jp", "iso-2022-jp", ""),
    ("whois.kg", "cp1251", ""),
    ("whois.nic.or.kr", "utf-8", ""),
    ("whois.kr", "utf-8", ""),
    ("whois.nic.kz", "utf-8", ""),
    ("whois.nic.li", "utf-8", ""),
    ("whois.domreg.lt", "utf-8", ""),
    ("whois.dns.lu", "iso-8859-1", ""),
    ("whois.marnet.mk", "utf-8", ""),
    ("whois.nic.mu", "utf-8", ""),
    ("whois.norid.no", "iso-8859-1", ""),
    ("whois.iis.nu", "utf-8", ""),
    ("whois.registry.om", "utf-8", ""),
    ("whois.registry.pf", "utf-8", ""),
    ("whois.dns.pt", "utf-8", ""),
    ("whois.registry.qa", "utf-8", ""),
    ("whois.nic.re", "utf-8", ""),
    ("whois.rnids.rs", "utf-8", ""),
    ("whois.nic.net.sa", "utf-8", ""),
    ("whois.iis.se", "utf-8", ""),
    ("whois.sgnic.sg", "utf-8", ""),
    ("whois.tld.sy", "utf-8", ""),
    ("whois.thains.co.th", "utf-8", ""),
    ("whois.ati.tn", "utf-8", ""),
    ("whois.trabis.gov.tr", "utf-8", ""),
    ("whois.twnic.net.tw", "utf-8", ""),
    ("whois.nic.ac.uk", "utf-8", ""),
    ("whois.gov.uk", "utf-8", ""),
    ("whois.biz.ua", "utf-8", ""),
    ("whois.co.ua", "utf-8", ""),
    ("whois.pp.ua", "utf-8", ""),
    ("whois.ua", "utf-8", ""),
    ("whois.nic.org.uy", "utf-8", ""),
    ("whois.nic.wf", "utf-8", ""),
    ("whois.nic.yt", "utf-8", ""),
    ("whois.nic.xn--otu796d", "utf-8", ""),
];

// ---------------------------------------------------------------------------
// 运行时解析（启动时构建一次，O(n) 且仅一次）。

use std::sync::OnceLock;

/// IPv4 表条目：(网络地址, 掩码, 服务器编码串)
pub struct Ip4Entry(pub u32, pub u32, pub &'static str);

fn parse_ip4_tables() -> Vec<Ip4Entry> {
    let mut out = Vec::with_capacity(512);
    for raw in IP4_RAW.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with("##") {
            continue;
        }
        if let Some(inner) = line.strip_prefix('{').and_then(|s| s.strip_suffix("},")) {
            // ip_del_recovered.h 格式：{ net, mask, "server" },
            let parts: Vec<&str> = inner.split(',').collect();
            if parts.len() == 3 {
                if let (Ok(net), Ok(mask)) = (parts[0].trim().parse::<u32>(), parts[1].trim().parse::<u32>()) {
                    let srv = parts[2].trim().trim_matches('"');
                    out.push(Ip4Entry(net, mask, Box::leak(srv.to_string().into_boxed_str())));
                }
            }
        } else if !line.starts_with("//") && !line.starts_with("/*") {
            // ip_del_list 格式：a.b.c.d/prefix<空白>server
            let mut it = line.split_whitespace();
            let (Some(cidr), Some(srv)) = (it.next(), it.next()) else { continue };
            if let Some((ip_s, prefix_s)) = cidr.split_once('/') {
                let octets: Vec<&str> = ip_s.split('.').collect();
                if octets.len() == 4 {
                    if let (Ok(a), Ok(b), Ok(c), Ok(d), Ok(p)) = (
                        octets[0].parse::<u32>(),
                        octets[1].parse::<u32>(),
                        octets[2].parse::<u32>(),
                        octets[3].parse::<u32>(),
                        prefix_s.parse::<u32>(),
                    ) {
                        if p <= 32 {
                            let net = (a << 24) | (b << 16) | (c << 8) | d;
                            let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
                            let srv = match srv {
                                "UNKNOWN" => "\u{5}",
                                "UNALLOCATED" => "\u{6}",
                                s if !s.contains('.') => Box::leak(format!("whois.{}.net", s).into_boxed_str()),
                                s => Box::leak(s.to_string().into_boxed_str()),
                            };
                            out.push(Ip4Entry(net, mask, srv));
                        }
                    }
                }
            }
        }
    }
    out
}

pub fn ip4_table() -> &'static [Ip4Entry] {
    static T: OnceLock<Vec<Ip4Entry>> = OnceLock::new();
    T.get_or_init(parse_ip4_tables)
}

fn parse_gtlds() -> Vec<&'static str> {
    NEW_GTLDS_RAW.split_whitespace().collect()
}

pub fn new_gtlds() -> &'static [&'static str] {
    static T: OnceLock<Vec<&'static str>> = OnceLock::new();
    T.get_or_init(parse_gtlds)
}
