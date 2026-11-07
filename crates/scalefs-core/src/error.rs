use crate::layout::DeviceId;
use crate::unicode::UnicodeVersion;
use std::fmt;

#[derive(Debug)]
pub enum ScaleFsError {
    Corrupt(&'static str),
    OutOfBounds {
        offset: u64,
        len: u64,
        device_len: u64,
    },
    InvalidArgument(&'static str),
    AlreadyExists,
    NotFound,
    NotDirectory,
    IsDirectory,
    DirectoryNotEmpty,
    TooManyLinks,
    OutOfSpace,
    Unsupported(&'static str),
    UnsupportedUnicodeVersion {
        pool: UnicodeVersion,
        newest: UnicodeVersion,
    },
    EarlierFormat {
        version: u32,
    },
    MissingMembers {
        missing: Vec<DeviceId>,
    },
    Io(std::io::Error),
}

pub(crate) const EARLIER_FORMAT_LEAD: &str =
    "this pool was created by an earlier preview of ScaleFS";

impl fmt::Display for ScaleFsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corrupt(what) => write!(f, "corrupt data: {what}"),
            Self::OutOfBounds {
                offset,
                len,
                device_len,
            } => write!(
                f,
                "request [{offset}, +{len}) is outside the device (len {device_len})"
            ),
            Self::InvalidArgument(what) => write!(f, "invalid argument: {what}"),
            Self::AlreadyExists => write!(f, "already exists"),
            Self::NotFound => write!(f, "not found"),
            Self::NotDirectory => write!(f, "not a directory"),
            Self::IsDirectory => write!(f, "is a directory"),
            Self::DirectoryNotEmpty => write!(f, "directory is not empty"),
            Self::TooManyLinks => write!(f, "too many links"),
            Self::OutOfSpace => write!(f, "out of space"),
            Self::Unsupported(what) => write!(f, "unsupported: {what}"),
            Self::UnsupportedUnicodeVersion { pool, newest } => write!(
                f,
                "this pool uses Unicode naming tables v{pool}; this ScaleFS \
                 carries up to v{newest} — upgrade ScaleFS to mount this pool"
            ),
            Self::EarlierFormat { version } => write!(
                f,
                "{EARLIER_FORMAT_LEAD} (on-disk format {version}; this build reads format {}): \
                 create a new pool and move the files",
                crate::format::FORMAT_VERSION
            ),
            Self::MissingMembers { missing } => {
                write!(f, "pool members are missing:")?;
                for id in missing {
                    write!(f, " ")?;
                    for byte in id.0 {
                        write!(f, "{byte:02x}")?;
                    }
                }
                Ok(())
            }
            Self::Io(err) => write!(f, "i/o error: {err}"),
        }
    }
}

impl std::error::Error for ScaleFsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ScaleFsError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

pub type Result<T> = std::result::Result<T, ScaleFsError>;
