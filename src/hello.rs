use std::fmt;
use std::io::{self, Read};
use byteorder::{ReadBytesExt, BigEndian};
use thiserror::Error;

use PeerIdentity;

#[derive(Debug)]
pub struct Hello {
  /// Use this peer in F2F mode. Do not gossip this hello.
  pub friend_only: bool,

  /// The identity of the peer.
  pub id: PeerIdentity,
}

#[derive(Debug, Error)]
pub enum HelloDeserializeError {
    #[error("Unexpected EOF when deserializing the hello")]
  ShortMessage
   ,
    #[error("There was an I/O error reading the hello. Error: {source}")]
  Io { #[from] source: io::Error }
   ,
}

impl Hello {
  pub fn deserialize<R>(r: &mut R) -> Result<Hello, HelloDeserializeError>
      where R: Read
  {
    let friend_only = match r.read_u32::<BigEndian>() {
      Ok(x)  => x != 0,
      Err(e) => return Err(match e.kind() {
        io::ErrorKind::UnexpectedEof => HelloDeserializeError::ShortMessage,
        _                            => HelloDeserializeError::Io { source: e },
      }),
    };
    let id = PeerIdentity::deserialize(r)?;
    Ok(Hello {
      friend_only: friend_only,
      id:          id,
    })
  }
}

impl fmt::Display for Hello {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "Hello!")
  }
}
