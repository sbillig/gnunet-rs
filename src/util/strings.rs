use base32;
use std::num::ParseIntError;
use std::str::FromStr;

#[derive(Debug, Error)]
pub enum ParseQuantityWithUnitsError {
    #[error("Failed to parse a number. Specifically: {source}")]
    ParseInt {
        #[from]
        source: ParseIntError,
    },
    #[error("Empty string given as argument")]
    EmptyString,
    #[error("Missing unit on the final number")]
    MissingUnit,
    #[error("Unrecognized unit. '{unit}' is not a valid unit")]
    NoSuchUnit { unit: String },
}

pub fn parse_quantity_with_units<'a>(
    s: &'a str,
    units: &[(&str, u64)],
) -> Result<u64, ParseQuantityWithUnitsError> {
    use self::ParseQuantityWithUnitsError::*;

    if s.trim().is_empty() {
        return Err(EmptyString);
    }

    let mut result = 0;
    let mut iter = s.split(' ');
    loop {
        match iter.next() {
            None => return Ok(result),
            Some(amount_str) => {
                if amount_str.is_empty() {
                    continue;
                } else {
                    let amount = u64::from_str(amount_str)?;
                    loop {
                        match iter.next() {
                            None => return Err(MissingUnit),
                            Some(unit) => {
                                if unit.is_empty() {
                                    continue;
                                } else {
                                    let mut found = false;
                                    for &(u, multiplier) in units.iter() {
                                        if u == unit {
                                            result += amount * multiplier;
                                            found = true;
                                            break;
                                        }
                                    }
                                    if found {
                                        break;
                                    } else {
                                        return Err(NoSuchUnit {
                                            unit: unit.to_string(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

pub fn crockford_base32_encode(b: &[u8]) -> String {
    base32::encode(base32::Alphabet::Crockford, b)
}

pub fn crockford_base32_decode(s: &str) -> Option<Vec<u8>> {
    base32::decode(base32::Alphabet::Crockford, s)
}
