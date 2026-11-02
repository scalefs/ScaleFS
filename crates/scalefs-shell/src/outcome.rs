use scalefs_ipc::json::Value;

pub const CR_SUCCESS: u32 = 0x00;
pub const CR_REMOVE_VETOED: u32 = 0x17;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    None,
    Prepared,
    Ejected,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    pub phase: Phase,
    pub generation: u64,
}

impl Record {
    pub fn from_reply(reply: &Value) -> Record {
        let phase = match reply.get("phase").and_then(Value::as_str) {
            Some("none") => Phase::None,
            Some("prepared") => Phase::Prepared,
            Some("ejected") => Phase::Ejected,
            _ => Phase::Unknown,
        };
        let generation = reply.get("generation").and_then(Value::as_u64).unwrap_or(0);
        Record { phase, generation }
    }

    pub fn is_new_removal(&self, before: Option<Record>) -> bool {
        if !matches!(self.phase, Phase::Prepared | Phase::Ejected) {
            return false;
        }
        match before {
            Some(earlier) if matches!(earlier.phase, Phase::Prepared | Phase::Ejected) => {
                self.generation > earlier.generation
                    || (earlier.phase == Phase::Prepared && self.phase == Phase::Ejected)
            }
            _ => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Serving {
    pub pool: String,
    pub pool_id: String,
}

impl Serving {
    pub fn from_reply(reply: &Value) -> Option<Serving> {
        Some(Serving {
            pool: reply.get("pool")?.as_str()?.to_string(),
            pool_id: reply.get("pool_id")?.as_str()?.to_string(),
        })
    }
}

pub fn instance_id(pool_id: &str) -> String {
    format!("SCALEFS\\VOLUME\\{}", pool_id.to_ascii_uppercase())
}

pub fn pool_id_from_device_name(name: &str) -> Option<String> {
    const PREFIX: &str = "\\Device\\ScaleFsVolume{";
    if !name.get(..PREFIX.len())?.eq_ignore_ascii_case(PREFIX) {
        return None;
    }
    let hex = name[PREFIX.len()..].strip_suffix('}')?;
    (hex.len() == 32 && hex.bytes().all(|unit| unit.is_ascii_hexdigit()))
        .then(|| hex.to_ascii_lowercase())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Holder {
    Share(String),
    Other(String),
}

pub fn holders(reply: Option<&Value>) -> Vec<Holder> {
    reply
        .and_then(|reply| reply.get("holders"))
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(|holder| {
            let kind = holder.get("kind")?.as_str()?;
            match (
                kind,
                holder.get("name").and_then(Value::as_str),
                holder.get("id").and_then(Value::as_u64),
            ) {
                ("share", Some(name), _) => Some(Holder::Share(name.to_string())),
                (_, Some(name), _) => Some(Holder::Other(format!("{kind} '{name}'"))),
                (_, None, Some(id)) => Some(Holder::Other(format!("{kind} job {id}"))),
                (_, None, None) => None,
            }
        })
        .collect()
}

pub fn holders_sentence(holders: &[Holder]) -> Option<String> {
    let shares: Vec<String> = holders
        .iter()
        .filter_map(|holder| match holder {
            Holder::Share(name) => Some(format!("'{name}'")),
            Holder::Other(_) => None,
        })
        .collect();
    let others: Vec<&str> = holders
        .iter()
        .filter_map(|holder| match holder {
            Holder::Other(phrase) => Some(phrase.as_str()),
            Holder::Share(_) => None,
        })
        .collect();
    let mut sentences = Vec::new();
    if !shares.is_empty() {
        sentences.push(format!(
            "ScaleFS is sharing this drive as {}.",
            shares.join(", ")
        ));
    }
    if !others.is_empty() {
        sentences.push(format!(
            "ScaleFS is using this drive: {}.",
            others.join(", ")
        ));
    }
    (!sentences.is_empty()).then(|| sentences.join(" "))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Ejected,
    Unconfirmed,
    Vetoed { holders: Vec<Holder> },
    NotRemoved,
    Failed { cr: u32 },
}

pub fn classify(
    cr: u32,
    before: Option<Record>,
    after: Option<Record>,
    holders: Vec<Holder>,
) -> Outcome {
    match cr {
        CR_SUCCESS => match after {
            Some(record) if record.is_new_removal(before) => match record.phase {
                Phase::Ejected => Outcome::Ejected,
                _ => Outcome::Unconfirmed,
            },
            Some(_) => Outcome::NotRemoved,
            None => Outcome::Unconfirmed,
        },
        CR_REMOVE_VETOED => Outcome::Vetoed { holders },
        other => Outcome::Failed { cr: other },
    }
}

pub fn drive_root_letter(path: &str) -> Option<char> {
    let mut chars = path.chars();
    let letter = chars.next()?;
    if !letter.is_ascii_alphabetic() || chars.next()? != ':' {
        return None;
    }
    match chars.as_str() {
        "" | "\\" => Some(letter.to_ascii_uppercase()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scalefs_ipc::json::parse;

    fn record(phase: Phase, generation: u64) -> Record {
        Record { phase, generation }
    }

    #[test]
    fn records_parse_and_unknown_is_the_fallback() {
        let reply = parse(r#"{"phase":"ejected","generation":3}"#).unwrap();
        assert_eq!(Record::from_reply(&reply), record(Phase::Ejected, 3));
        let reply = parse(r#"{"phase":"none"}"#).unwrap();
        assert_eq!(Record::from_reply(&reply), record(Phase::None, 0));
        let reply = parse(r#"{"phase":"sideways"}"#).unwrap();
        assert_eq!(Record::from_reply(&reply).phase, Phase::Unknown);
    }

    #[test]
    fn only_a_newer_removal_counts() {
        let ejected1 = record(Phase::Ejected, 1);
        let ejected2 = record(Phase::Ejected, 2);
        let prepared2 = record(Phase::Prepared, 2);
        assert!(ejected2.is_new_removal(None));
        assert!(ejected2.is_new_removal(Some(record(Phase::None, 0))));
        assert!(ejected2.is_new_removal(Some(ejected1)));
        assert!(!ejected1.is_new_removal(Some(ejected1)));
        assert!(ejected2.is_new_removal(Some(prepared2)));
        assert!(!record(Phase::None, 0).is_new_removal(None));
        assert!(!record(Phase::Unknown, 9).is_new_removal(None));
    }

    #[test]
    fn classification_reads_the_record_not_the_api_result() {
        let before = Some(record(Phase::None, 0));
        assert_eq!(
            classify(CR_SUCCESS, before, Some(record(Phase::Ejected, 1)), vec![]),
            Outcome::Ejected
        );
        assert_eq!(
            classify(CR_SUCCESS, before, Some(record(Phase::Prepared, 1)), vec![]),
            Outcome::Unconfirmed
        );
        assert_eq!(
            classify(CR_SUCCESS, before, Some(record(Phase::None, 0)), vec![]),
            Outcome::NotRemoved
        );
        assert_eq!(
            classify(CR_SUCCESS, before, None, vec![]),
            Outcome::Unconfirmed
        );
        assert_eq!(
            classify(
                CR_REMOVE_VETOED,
                before,
                None,
                vec![Holder::Share("x".into())]
            ),
            Outcome::Vetoed {
                holders: vec![Holder::Share("x".into())]
            }
        );
        assert_eq!(
            classify(0x33, before, None, vec![]),
            Outcome::Failed { cr: 0x33 }
        );
    }

    #[test]
    fn the_serving_and_its_device_come_from_the_reply() {
        let reply = parse(
            r#"{"pool_id":"887409c8","phase":"none","generation":0,"pool":"dl","mount":"P:","holders":[]}"#,
        )
        .unwrap();
        assert_eq!(
            Serving::from_reply(&reply),
            Some(Serving {
                pool: "dl".into(),
                pool_id: "887409c8".into()
            })
        );
        let gone = parse(r#"{"pool_id":"887409c8","phase":"ejected","generation":2}"#).unwrap();
        assert_eq!(Serving::from_reply(&gone), None);
        assert_eq!(instance_id("887409c8"), "SCALEFS\\VOLUME\\887409C8");
    }

    #[test]
    fn holders_read_as_shares_and_phrases() {
        let reply = parse(
            r#"{"holders":[{"kind":"share","name":"docs"},{"kind":"scrub","id":7},
                {"kind":"export","name":"nfs1"},{"kind":"odd"},{"name":"no kind"}]}"#,
        )
        .unwrap();
        assert_eq!(
            holders(Some(&reply)),
            vec![
                Holder::Share("docs".into()),
                Holder::Other("scrub job 7".into()),
                Holder::Other("export 'nfs1'".into()),
            ]
        );
        assert!(holders(None).is_empty());
        assert!(holders(Some(&parse(r#"{"holders":[]}"#).unwrap())).is_empty());
    }

    #[test]
    fn the_in_use_sentence_says_what_scalefs_holds() {
        let share = |name: &str| Holder::Share(name.into());
        let other = |phrase: &str| Holder::Other(phrase.into());
        assert_eq!(
            holders_sentence(&[share("dlshare")]).as_deref(),
            Some("ScaleFS is sharing this drive as 'dlshare'.")
        );
        assert_eq!(
            holders_sentence(&[share("a"), share("b")]).as_deref(),
            Some("ScaleFS is sharing this drive as 'a', 'b'.")
        );
        assert_eq!(
            holders_sentence(&[other("scrub job 7")]).as_deref(),
            Some("ScaleFS is using this drive: scrub job 7.")
        );
        assert_eq!(
            holders_sentence(&[other("scrub job 7"), share("a"), other("export 'n'")]).as_deref(),
            Some(
                "ScaleFS is sharing this drive as 'a'. \
                 ScaleFS is using this drive: scrub job 7, export 'n'."
            )
        );
        assert_eq!(holders_sentence(&[]), None);
    }

    #[test]
    fn the_pool_comes_from_the_volume_device_name() {
        let id = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            pool_id_from_device_name("\\Device\\ScaleFsVolume{0123456789abcdef0123456789abcdef}")
                .as_deref(),
            Some(id)
        );
        assert_eq!(
            pool_id_from_device_name("\\DEVICE\\scalefsvolume{0123456789ABCDEF0123456789ABCDEF}")
                .as_deref(),
            Some(id)
        );
        assert_eq!(
            instance_id(id),
            "SCALEFS\\VOLUME\\0123456789ABCDEF0123456789ABCDEF"
        );
        for other in [
            "",
            "\\Device\\HarddiskVolume3",
            "\\Device\\CdRom0",
            "\\Device\\ScaleFsVolume{}",
            "\\Device\\ScaleFsVolume{0123456789abcdef0123456789abcde}",
            "\\Device\\ScaleFsVolume{0123456789abcdef0123456789abcdef0}",
            "\\Device\\ScaleFsVolume{0123456789abcdef0123456789abcdeg}",
            "\\Device\\ScaleFsVolume{0123456789abcdef0123456789abcdef",
            "\\Device\\ScaleFsVolume{0123456789abcdef0123456789abcdef}\\x",
            "\\Device\\ScaleFsVolume0123456789abcdef0123456789abcdef}",
            "\\Device\\ScaleFsVolume{0123456789abcdef-123456789abcdef}",
        ] {
            assert_eq!(pool_id_from_device_name(other), None, "{other}");
        }
    }

    #[test]
    fn drive_roots_only() {
        assert_eq!(drive_root_letter("P:\\"), Some('P'));
        assert_eq!(drive_root_letter("p:"), Some('P'));
        assert_eq!(drive_root_letter("P:\\docs"), None);
        assert_eq!(drive_root_letter("\\\\server\\share"), None);
        assert_eq!(drive_root_letter(""), None);
    }
}
