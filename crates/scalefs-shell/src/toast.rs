pub fn xml(title: &str, body: &str) -> String {
    format!(
        "<toast><visual><binding template=\"ToastGeneric\"><text>{}</text><text>{}</text>\
         </binding></visual></toast>",
        escape(title),
        escape(body)
    )
}

pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for unit in text.chars() {
        match unit {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(unit),
            control if control < ' ' => {}
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_payload_is_the_generic_template_with_two_lines() {
        assert_eq!(
            xml(
                "Safe To Remove Hardware",
                "This device can now be safely removed."
            ),
            "<toast><visual><binding template=\"ToastGeneric\">\
             <text>Safe To Remove Hardware</text>\
             <text>This device can now be safely removed.</text>\
             </binding></visual></toast>"
        );
    }

    #[test]
    fn reserved_characters_are_escaped() {
        assert_eq!(
            escape(r#"a & b < c > d " e ' f"#),
            "a &amp; b &lt; c &gt; d &quot; e &apos; f"
        );
        assert_eq!(escape("&amp;"), "&amp;amp;");
        assert_eq!(escape("ScaleFS volume"), "ScaleFS volume");
        assert_eq!(
            xml("T", "The 'ScaleFS volume' device"),
            "<toast><visual><binding template=\"ToastGeneric\"><text>T</text>\
             <text>The &apos;ScaleFS volume&apos; device</text></binding></visual></toast>"
        );
    }

    #[test]
    fn disallowed_control_characters_are_dropped() {
        assert_eq!(escape("a\u{0}b\u{1b}c\u{1f}d"), "abcd");
        assert_eq!(escape("tab\tline\ncr\r"), "tab\tline\ncr\r");
    }

    #[test]
    fn a_hostile_name_stays_text() {
        let payload = xml("T", "</text><actions><action/></actions><text>");
        assert_eq!(payload.matches("<text>").count(), 2);
        assert_eq!(payload.matches("</text>").count(), 2);
        assert!(!payload.contains("<actions>"));
        assert!(!payload.contains("<action/>"));
    }

    #[test]
    fn nothing_beyond_the_two_lines() {
        let payload = xml("T", "B");
        for absent in [
            "launch", "<actions", "<audio", "duration", "scenario", "<image",
        ] {
            assert!(!payload.contains(absent), "{absent} in {payload}");
        }
    }
}
