use std::num::ParseIntError;
use std::str::FromStr;

error_def! ParseQuantityWithUnitsError {
    ParseInt { #[from] cause: ParseIntError }
        => "Failed to parse a number" ("Specifically: {}", cause),
    EmptyString
        => "Empty string given as argument",
    MissingUnit
        => "Missing unit on the final number",
    NoSuchUnit { unit: String }
        => "Unrecognized unit" ("\"{}\" is not a valid unit", unit),
}

pub fn parse_quantity_with_units<'a>(s: &'a str, units: &[(&str, u64)]) -> Result<u64, ParseQuantityWithUnitsError> {
    use self::ParseQuantityWithUnitsError::*;

    if s.trim().is_empty() {
        return Err(EmptyString);
    }

    let mut result = 0;
    let mut iter = s.split(' ');
    loop {
        match iter.next() {
            None             => return Ok(result),
            Some(amount_str) => {
                if amount_str.is_empty() {
                    continue;
                }
                else {
                    let amount = try!(u64::from_str(amount_str));
                    loop {
                        match iter.next() {
                            None       => return Err(MissingUnit),
                            Some(unit) => {
                                if unit.is_empty() {
                                    continue;
                                }
                                else {
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
                                    }
                                    else {
                                        return Err(NoSuchUnit { unit: unit.to_string() });
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

pub fn data_to_string(data: &[u8]) -> String {
    let enc_table = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let mut out = String::new();

    let mut rpos: usize = 0;
    let mut bits: u32 = 0;
    let mut vbit: u32 = 0;
    let size: usize = data.len();

    while (rpos < size) || (vbit > 0) {
        if (rpos < size) && (vbit < 5) {
            let b = data[rpos] as u32;
            rpos += 1;

            let s: u32 = if b >= 0 { b } else { 256 + b };

            bits = (bits << 8) | s;
            vbit += 8;
        }
        if vbit < 5 {
            bits <<= 5 - vbit;
            vbit = 5;
        }
        let pos = ((bits >> (vbit - 5)) & 31) as usize;
        out.push_str(&enc_table[pos..pos+1]);
        vbit -= 5;
    }
    assert!(out.len() == get_encoded_string_len(data.len()));
    out
}

fn get_encoded_string_len(data_size: usize) -> usize {
    return (data_size * 8 + 4) / 5;
}
