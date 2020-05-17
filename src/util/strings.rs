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

            bits = (bits << 8) | b;
            vbit += 8;
        }
        if vbit < 5 {
            bits <<= 5 - vbit;
            vbit = 5;
        }
        let pos = ((bits >> (vbit - 5)) & 31) as usize;
        out.push_str(&enc_table[pos..pos + 1]);
        vbit -= 5;
    }
    assert!(out.len() == get_encoded_string_len(data.len()));
    out
}

pub fn string_to_data(string: &str, out_data: &mut [u8]) -> bool {
    let mut rpos: usize;
    let mut wpos: usize;
    let mut bits: i64;
    let mut vbit: i64;
    let mut ret: i64;
    let shift: i64;
    let enc_len = string.len();
    let encoded_len = out_data.len() * 8;

    if 0 == enc_len {
        if 0 == encoded_len {
            return true;
        }
        return false;
    }

    wpos = out_data.len();
    rpos = enc_len;

    if encoded_len % 5 > 0 {
        // padding!
        vbit = encoded_len as i64 % 5;
        shift = 5 - vbit;

        rpos -= 1;
        ret = get_value(string.as_bytes()[rpos]) as i64;
        bits = ret >> (5 - (encoded_len % 5));
    } else {
        vbit = 5;
        shift = 0;
        rpos -= 1;
        ret = get_value(string.as_bytes()[rpos]) as i64;
        bits = ret;
    }
    if (encoded_len + shift as usize) / 5 != enc_len {
        return false;
    }
    if -1 == ret {
        return false;
    }
    while wpos > 0 {
        assert!(rpos != 0);
        rpos -= 1;
        ret = get_value(string.as_bytes()[rpos]) as i64;
        bits = ret << vbit | bits;
        if -1 == ret {
            return false;
        }
        vbit += 5;
        if vbit >= 8 {
            wpos -= 1;
            out_data[wpos] = bits as u8;
            bits >>= 8;
            vbit -= 8;
        }
    }
    if rpos != 0 || vbit != 0 {
        return false;
    }
    true
}

fn get_encoded_string_len(data_size: usize) -> usize {
    return (data_size * 8 + 4) / 5;
}

fn get_value(a: u8) -> i32 {
    //       '0'          '9'
    if (a >= 48) && (a <= 57) {
        return a as i32 - 48;
    }
    //       'A'          'V'
    if (a >= 65) && (a <= 86) {
        return a as i32 - 65 + 10;
    }
    return -1;
}

#[test]
fn test_string_data_conversion_simple() {
    let str_data = "GNUnet".to_string();
    let data = str_data.as_bytes();

    let string = data_to_string(data);
    let data2 = &mut [0; 6];

    assert!(string_to_data(&string, data2));
    assert!(data == data2);
}

#[test]
fn test_string_data_conversion() {
    let string = "22HTJH6O3EJ1FJ2S23JVQ7G1TMQI22VFDDJCD76MB6SQ8G3RVH40";
    let data = &mut [0; 32];

    assert!(string_to_data(string, data));
    assert!(data_to_string(data) == string);
}
