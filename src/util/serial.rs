use byteorder::BigEndian;
use smallvec::SmallVec;
use std::str;
pub use zerocopy::{AsBytes, FromBytes, LayoutVerified, U16, U32, U64};

#[allow(non_camel_case_types)]
pub type u16be = U16<BigEndian>;
#[allow(non_camel_case_types)]
pub type u32be = U32<BigEndian>;
#[allow(non_camel_case_types)]
pub type u64be = U64<BigEndian>;

pub type Buffer = SmallVec<[u8; 64]>;

pub fn try_cast<T: FromBytes>(b: &[u8]) -> Option<&T> {
    let o: Option<LayoutVerified<&[u8], T>> = LayoutVerified::new(b);
    o.map(|l| l.into_ref())
}

pub fn try_cast_prefix<T: FromBytes>(b: &[u8]) -> Option<(&T, &[u8])> {
    let o: Option<(LayoutVerified<&[u8], T>, &[u8])> = LayoutVerified::new_from_prefix(b);
    o.map(|(l, b)| (l.into_ref(), b))
}

pub fn try_parse_prefix_and_str<T: FromBytes>(b: &[u8]) -> Option<(&T, &str)> {
    let (prefix, rest) = try_cast_prefix::<T>(b)?;
    Some((prefix, str_from_cstr(rest)?))
}

pub fn cast<T: FromBytes>(b: &[u8]) -> &T {
    try_cast(b).unwrap()
}

pub fn str_from_cstr(b: &[u8]) -> Option<&str> {
    if b.len() == 0 {
        str::from_utf8(&b).ok()
    } else {
        str::from_utf8(&b[..(b.len() - 1)]).ok()
    }
}

/// The matched element is not included in the returned subslices.
pub fn split_on<T: PartialEq>(b: &[T], m: T) -> Option<(&[T], &[T])> {
    let mut i = 0;
    for e in b {
        if e == &m {
            let (head, tail) = b.split_at(i); // tail starts with match element
            return Some((head, &tail[1..]));
        }
        i += 1
    }
    None
}

pub fn parse_leading_cstr(b: &[u8]) -> Option<(&str, &[u8])> {
    let (s, rest) = split_on(b, 0)?;
    if s.is_empty() {
        None
    } else {
        Some((str::from_utf8(s).ok()?, rest))
    }
}

pub fn try_split_at(b: &[u8], i: usize) -> Option<(&[u8], &[u8])> {
    if i <= b.len() {
        Some(b.split_at(i))
    } else {
        None
    }
}

#[test]
fn test_split_on() {
    assert!(split_on(&[], 123).is_none());

    let b = ['a', 'b', '\0', 'c', 'd'];
    let (head, tail) = split_on(&b, '\0').unwrap();
    assert_eq!(head, &['a', 'b']);
    assert_eq!(tail, &['c', 'd']);

    assert!(split_on(&b, 'x').is_none());
    assert_eq!(split_on(&b, 'a').unwrap(), (&[][..], &b[1..]));
    assert_eq!(split_on(&b, 'd').unwrap(), (&b[..4], &[][..]));
}
