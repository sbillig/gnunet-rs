use self::RecordType::*;
use byteorder::{BigEndian, ReadBytesExt};
use num::FromPrimitive;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::io::{self, Read};
use std::str::FromStr;
use util::io::ReadUtil;

/// An enum of the different GNS record types.
///
/// Some of these records exist in the legacy DNS (but are still used in GNS). Others are specific
/// to GNS. These are marked **Legacy** and **GNS** respectively.
#[derive(Copy, Clone, Debug, FromPrimitive, PartialEq, Eq)]
pub enum RecordType {
    /// **Legacy.** Address record. Stores a 32bit IPv4 address.
    A = 1,
    /// **Legacy.** Name server record. Delegates a DNS zone to use the given authoritative name servers.
    NS = 2,
    /// **Legacy.** Canonical name record. Alias of one name to another.
    CNAME = 5,
    /// **Legacy.** Start of authority record. Specifies authoritative information about a DNS zone.
    SOA = 6,
    /// **Legacy.** Pointer record. Pointer to a canonical name.
    PTR = 12,
    /// **Legacy.** Mail exchange record. Maps a domain name to a list of message transfer agents for that
    /// domain.
    MX = 15,
    /// **Legacy.** Text record. Used to store human-readable data and various forms of machine-readable data.
    TXT = 16,
    /// **Legacy.** Address record. Stores a 128bit IPv6 address.
    AAAA = 28,
    /// **Legacy.** TLSA certificate association. A record for DNS-based Authentication of Named Entities (DANE).
    TLSA = 52,

    /// **GNS.** Petname key record. Used to delegate to other users' zones and give those zones a petname.
    PKEY = 65536,
    /// **GNS.** Nickname record. Used to give a zone a name.
    NICK = 65537,
    /// **GNS.** Legacy hostname record.
    LEHO = 65538,
    /// **GNS.** Virtual public network record.
    VPN = 65539,
    /// **GNS.** GNS2DNS record. Used to delegate authority to a legacy DNS zone.
    GNS2DNS = 65540,
}

/// Error generated when attempting to parse a `RecordType`
#[derive(Debug, Error)]
pub enum RecordTypeFromStrError {
    #[error("Failed to parse the string as a RecordType")]
    ParsingFailed,
}

impl FromStr for RecordType {
    type Err = RecordTypeFromStrError;

    fn from_str(s: &str) -> Result<RecordType, RecordTypeFromStrError> {
        match s {
            "A" => Ok(A),
            "NS" => Ok(NS),
            "CNAME" => Ok(CNAME),
            "SOA" => Ok(SOA),
            "PTR" => Ok(PTR),
            "MX" => Ok(MX),
            "TXT" => Ok(TXT),
            "AAAA" => Ok(AAAA),
            "TLSA" => Ok(TLSA),

            "PKEY" => Ok(PKEY),
            "NICK" => Ok(NICK),
            "LEHO" => Ok(LEHO),
            "VPN" => Ok(VPN),
            "GNS2DNS" => Ok(GNS2DNS),
            _ => Err(RecordTypeFromStrError::ParsingFailed),
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

bitflags! {
    pub struct RecordFlags: u32 {
        const NONE = 0;
        const PRIVATE = 2;
        const PENDING = 4;
        const RELATIVE_EXPIRATION = 8;
        const SHADOW_RECORD = 16;
    }
}

/// A record in the GNU Name System.
#[derive(Clone)]
pub struct Record {
    pub data: Vec<u8>,
    pub expiration_time: u64,
    pub data_size: usize,
    pub record_type: RecordType,
    pub flags: RecordFlags,
}

impl Record {
    /// Deserialize a record from a byte stream.
    pub fn deserialize<T>(reader: &mut T) -> Result<Record, io::Error>
    where
        T: Read,
    {
        let expiration_time = reader.read_u64::<BigEndian>()?;
        let data_size = reader.read_u32::<BigEndian>()? as usize;
        // TODO: handle invalid recordtype
        let record_type = RecordType::from_u32(reader.read_u32::<BigEndian>()?).unwrap();
        // TODO: handle invalid flags
        let flags = RecordFlags::from_bits_truncate(reader.read_u32::<BigEndian>()?);
        let data = reader.read_exact_alloc(data_size as usize)?;

        Ok(Record {
            data,
            expiration_time,
            data_size,
            record_type,
            flags,
        })
    }

    /// Get the type of a record.
    pub fn record_type(&self) -> RecordType {
        self.record_type
    }
}

impl Debug for Record {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // TODO properly implement ll::GNUNET_GNSRECORD_value_to_string
        assert!(self.data.len() == 4);
        let addr =
            ::std::net::Ipv4Addr::new(self.data[0], self.data[1], self.data[2], self.data[3]);
        addr.fmt(f)
    }
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}
