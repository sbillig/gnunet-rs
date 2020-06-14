use crate::util;
use crate::util::serial::*;
use chrono::{DateTime, Local, TimeZone, Utc};
use std::convert::TryInto;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

#[derive(Copy, Clone, Debug, PartialEq, AsBytes, FromBytes)]
#[repr(C)]
pub struct Absolute {
    micros: u64be,
}

impl Absolute {
    pub fn forever() -> Absolute {
        Absolute {
            micros: u64be::new(u64::MAX),
        }
    }

    pub fn is_forever(&self) -> bool {
        self.micros.get() == u64::MAX
    }
}

impl fmt::Display for Absolute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_forever() {
            write!(f, "end of time")
        } else {
            // TODO: check if expir fits in i64
            let nanos: i64 = (self.micros.get() * 1000).try_into().unwrap();
            let utc = Utc.timestamp_nanos(nanos);
            let local = DateTime::<Local>::from(utc);
            write!(f, "{}", local)
        }
    }
}

pub struct Relative {
    micros: u64,
}

static RELATIVE_UNITS: [(&str, u64); 17] = [
    ("us", 1),
    ("ms", 1000),
    ("s", 1000 * 1000),
    ("\"", 1000 * 1000),
    ("m", 60 * 1000 * 1000),
    ("min", 60 * 1000 * 1000),
    ("minutes", 60 * 1000 * 1000),
    ("'", 60 * 1000 * 1000),
    ("h", 60 * 60 * 1000 * 1000),
    ("d", 24 * 60 * 60 * 1000 * 1000),
    ("day", 24 * 60 * 60 * 1000 * 1000),
    ("days", 24 * 60 * 60 * 1000 * 1000),
    ("week", 7 * 24 * 60 * 60 * 1000 * 1000),
    ("weeks", 7 * 24 * 60 * 60 * 1000 * 1000),
    ("year", 31_536_000_000_000 /* year */),
    ("years", 31_536_000_000_000 /* year */),
    ("a", 31_536_000_000_000 /* year */),
];

impl FromStr for Relative {
    type Err = util::strings::ParseQuantityWithUnitsError;
    fn from_str(s: &str) -> Result<Relative, util::strings::ParseQuantityWithUnitsError> {
        let micros = util::strings::parse_quantity_with_units(s, &RELATIVE_UNITS[..])?;
        Ok(Relative { micros })
    }
}

impl From<Duration> for Relative {
    fn from(d: Duration) -> Relative {
        Relative {
            micros: d
                .as_secs()
                .checked_mul(1_000_000)
                .and_then(|n| n.checked_add(d.subsec_nanos() as u64))
                .unwrap_or(u64::MAX),
        }
    }
}

impl From<Relative> for Duration {
    fn from(r: Relative) -> Duration {
        if r.micros == u64::MAX {
            Duration::new(u64::MAX, u32::MAX)
        } else {
            Duration::new(r.micros / 1_000_000, ((r.micros % 1_000_000) as u32) * 1000)
        }
    }
}

#[cfg(tests)]
mod test {
    #[test]
    pub fn from_str_works() {
        let r = Relative::from_str(" 3   min  10 s   ");
        assert_eq!(r.micros, 190_000_000);
    }

    #[test]
    #[should_panic]
    pub fn parse_invalid_unit() {
        Relative::from_str("3 balls").unwrap();
    }

    #[test]
    #[should_panic]
    pub fn parse_no_unit() {
        Relative::from_str("12").unwrap();
    }

    #[test]
    #[should_panic]
    pub fn parse_empty_string() {
        Relative::from_str("").unwrap();
    }

    #[test]
    #[should_panic]
    pub fn empty_string() {
        Relative::from_str("").unwrap();
    }

    #[test]
    #[should_panic]
    pub fn parse_no_coefficient() {
        Relative::from_str("days").unwrap();
    }
}
