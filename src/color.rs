// ANSI 彩色输出支持：调色板、终端检测、CJK 宽度计算。

use std::sync::OnceLock;

#[derive(Clone, Copy, PartialEq)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

static COLOR_ON: OnceLock<bool> = OnceLock::new();

pub fn init_color(mode: ColorMode, stdout_tty: bool) {
    let on = match mode {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => {
            if std::env::var_os("NO_COLOR").is_some() {
                false
            } else {
                stdout_tty && std::env::var_os("TERM").map_or(false, |t| t != "dumb")
            }
        }
    };
    let _ = COLOR_ON.set(on);
}

pub fn color_on() -> bool {
    *COLOR_ON.get().unwrap_or(&false)
}

/// 样式码；颜色关闭时全部为空串。
macro_rules! style {
    ($name:ident, $code:expr) => {
        pub fn $name() -> &'static str {
            if color_on() {
                $code
            } else {
                ""
            }
        }
    };
}

style!(reset, "\x1b[0m");
style!(bold, "\x1b[1m");
style!(italic, "\x1b[3m");

style!(fg_frame, "\x1b[38;5;60m"); // 边框：暗蓝灰
style!(fg_title, "\x1b[1;38;5;87m"); // 标题：亮青
style!(fg_query, "\x1b[1;38;5;231m"); // 查询词：纯白
style!(fg_server, "\x1b[1;38;5;75m"); // 服务器名：天蓝
style!(fg_badge, "\x1b[38;5;16;48;5;117m"); // 徽章：深蓝字/亮青底
style!(fg_key, "\x1b[38;5;110m"); // 原始键名：灰蓝
style!(fg_label, "\x1b[1;38;5;153m"); // 中文标签：亮天蓝
style!(fg_value, "\x1b[37m"); // 值：白
style!(fg_dim, "\x1b[38;5;245m"); // 次要信息
style!(fg_date, "\x1b[38;5;220m"); // 日期：金
style!(fg_email, "\x1b[4;38;5;156m"); // 邮箱：绿+下划线
style!(fg_url, "\x1b[4;38;5;111m"); // 链接：蓝+下划线
style!(fg_ip, "\x1b[38;5;159m"); // IP：青
style!(fg_ns, "\x1b[38;5;183m"); // 域名服务器：浅紫
style!(fg_org, "\x1b[1;38;5;215m"); // 组织/注册商：橙
style!(fg_status_ok, "\x1b[38;5;82m"); // 状态正常：绿
style!(fg_status_warn, "\x1b[38;5;226m"); // 状态警告：黄
style!(fg_redacted, "\x1b[38;5;240m"); // 已隐藏：深灰
style!(fg_comment, "\x1b[2;38;5;244m"); // 注释/横幅
style!(fg_banner, "\x1b[38;5;109m"); // 引荐横幅
style!(fg_error, "\x1b[1;38;5;203m"); // 错误

/// 终端宽度；优先 COLUMNS 环境变量，默认 80。
pub fn term_width() -> usize {
    if let Ok(v) = std::env::var("COLUMNS") {
        if let Ok(n) = v.trim().parse::<usize>() {
            if n >= 20 {
                return n;
            }
        }
    }
    80
}

/// 单个字符的显示宽度（0/1/2）。
pub fn char_width(c: char) -> usize {
    let cp = c as u32;
    if cp == 0 || cp < 32 || (0x7f..0xa0).contains(&cp) {
        return 0;
    }
    // 组合字符
    if (0x300..0x370).contains(&cp)
        || (0x483..0x48a).contains(&cp)
        || (0x591..0x5c8).contains(&cp)
        || (0x610..0x62c).contains(&cp)
        || (0x64b..0x660).contains(&cp)
        || (0x20d0..0x2100).contains(&cp)
        || (0xfe00..0xfe10).contains(&cp)
        || (0xfe20..0xfe30).contains(&cp)
        || (0xe0001..=0xe01ef).contains(&cp)
    {
        return 0;
    }
    // 宽字符：CJK、全角、Hangul、emoji
    if (0x1100..0x1160).contains(&cp)
        || (0x2e80..0xa4d0).contains(&cp)
        || (0xa960..0xa980).contains(&cp)
        || (0xac00..0xd7a4).contains(&cp)
        || (0xf900..0xfb00).contains(&cp)
        || (0xfe30..0xfe70).contains(&cp)
        || (0xff00..0xff61).contains(&cp)
        || (0xffe0..0xffe7).contains(&cp)
        || (0x1f300..0x1f650).contains(&cp)
        || (0x1f900..0x1fa00).contains(&cp)
        || (0x20000..0x2fffe).contains(&cp)
        || (0x30000..0x3fffe).contains(&cp)
    {
        return 2;
    }
    1
}

/// 字符串显示宽度。
pub fn str_width(s: &str) -> usize {
    s.chars().map(char_width).sum()
}

/// 按显示宽度截断（保留宽字符完整性）。
pub fn truncate_width(s: &str, max: usize) -> String {
    let mut w = 0;
    let mut out = String::new();
    for c in s.chars() {
        let cw = char_width(c);
        if w + cw > max {
            break;
        }
        w += cw;
        out.push(c);
    }
    out
}

/// 在右侧填充空格到指定显示宽度。
pub fn pad_to(s: &str, width: usize) -> String {
    let w = str_width(s);
    if w >= width {
        s.to_string()
    } else {
        format!("{}{}", s, " ".repeat(width - w))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widths() {
        assert_eq!(str_width("hello"), 5);
        assert_eq!(str_width("中文"), 4);
        assert_eq!(str_width("a中b"), 4);
        assert_eq!(str_width("🔒"), 2);
    }

    #[test]
    fn padding() {
        let p = pad_to("中文", 6);
        assert_eq!(str_width(&p), 6);
    }
}
