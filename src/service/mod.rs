//! Module for communicating with GNUnet services. Implements the parts of the GNUnet IPC protocols
//! that are common to all services.

use crate::configuration::{self, Cfg};
use crate::MessageType;

use async_std::io;
use async_std::os::unix::net::UnixStream;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use std::convert::TryInto;
use std::fmt;
use tracing::{debug, instrument};

#[repr(C, packed)]
pub struct MessageHeader {
    len: u16, // bigendian
    typ: u16, // bigendian
}

impl MessageHeader {
    pub fn new(len: u16, msg_type: MessageType) -> Self {
        MessageHeader {
            len: len.to_be(),
            typ: (msg_type as u16).to_be(),
        }
    }

    pub fn length(&self) -> u16 {
        self.len.to_le()
    }

    pub fn msg_type_u16(&self) -> u16 {
        self.typ.to_le()
    }

    pub fn msg_type(&self) -> Option<MessageType> {
        MessageType::from_u16(self.msg_type_u16())
    }
}

pub trait MessageTrait {
    fn into_slice(&self) -> &[u8];
}

/// Created by `service::connect`. Used to read messages from a GNUnet service.
pub struct ServiceConnection {
    name: String,
    inner: UnixStream,
}

impl ServiceConnection {
    /// Sends a message to the connected socket.
    ///
    /// The message should not have a null-terminated string, otherwise use `send_with_str`.
    pub async fn send<T: MessageTrait>(&mut self, message: T) -> Result<(), io::Error> {
        self.inner.write_all(message.into_slice()).await
    }

    /// Sends a message with a null-terminated string to the connected socket.
    ///
    /// The caller needs to ensure that the message corresponds to the string, i.e. the message length should add up.
    pub async fn send_with_str<T: MessageTrait>(
        &mut self,
        message: T,
        string: &str,
    ) -> Result<(), io::Error> {
        self.inner.write_all(message.into_slice()).await?;
        self.inner.write_all(string.as_bytes()).await?;
        self.inner.write_all(&[0u8]).await?;
        Ok(())
    }

    #[instrument]
    pub async fn recv(&mut self) -> Result<(u16, Vec<u8>), io::Error> {
        let mut head = [0u8; 4];
        self.inner.read_exact(&mut head).await?;

        let len = u16::from_be_bytes(head[0..2].try_into().unwrap());
        let msg_type = u16::from_be_bytes(head[2..].try_into().unwrap());

        debug!(
            type_u16 = msg_type,
            len,
            "type: {:?}",
            MessageType::from_u16(msg_type)
        );

        let rem = len - 4; // len includes header (except for some msg types? TODO)

        let mut rest = vec![0; rem as usize];
        self.inner.read_exact(&mut rest).await?;

        Ok((msg_type, rest))
    }

    pub fn from_stream(name: String, inner: UnixStream) -> Self {
        ServiceConnection { name, inner }
    }
}

impl fmt::Debug for ServiceConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceConnection")
            .field("name", &self.name)
            .finish()
    }
}

/// Attempt to connect to the local GNUnet service named `name`.
///
/// eg. `connect(&cfg, "arm")` will attempt to connect to the locally-running `gnunet-arm` service
/// using the congfiguration details (eg. socket address, port etc.) in `cfg`.
pub async fn connect(cfg: &Cfg, name: &str) -> Result<ServiceConnection, ConnectError> {
    let path = cfg.get_filename(name, "UNIXPATH")?;
    let sock = UnixStream::connect(&path).await?;

    // see gnunet/src/util/client.c::start_connect
    // TODO: tcp

    Ok(ServiceConnection {
        name: name.to_string(),
        inner: sock,
    })
}

/// Error that can be generated when attempting to connect to a service.
#[derive(Debug, Error)]
pub enum ConnectError {
    #[error("The configuration does not describe how to connect to the service.\nConfig does not contain an entry for UNIXPATH in the service's section: {source}")]
    NotConfigured {
        #[from]
        source: configuration::CfgGetFilenameError,
    },
    #[error("There was an I/O error communicating with the service. Specifically {source}")]
    Io {
        #[from]
        source: io::Error,
    },
}

#[macro_export]
macro_rules! message_to_slice {
    ($t:ty, $i:ident) => {{
        use std::mem;
        use std::slice;
        let p: *const $t = $i;
        let p: *const u8 = p as *const u8;
        let res: &[u8] = unsafe { slice::from_raw_parts(p, mem::size_of::<$t>()) };
        res
    }};
}

#[test]
fn test_message_to_slice() {
    #[repr(C, packed)]
    struct S {
        a: u16,
        b: u32,
    }

    let s = &S { a: 0, b: 0 };
    let slice = message_to_slice!(S, s);

    assert!(slice.iter().all(|&x| x == 0));
    assert_eq!(slice.len(), 6);
}

#[async_std::test]
async fn test_service() {
    use async_std::os::unix::net::UnixStream;
    use std::mem::size_of;

    #[repr(C, packed)]
    struct DummyMsg {
        header: MessageHeader,
        body: [u8; 4],
    }

    impl MessageTrait for DummyMsg {
        fn into_slice(&self) -> &[u8] {
            message_to_slice!(DummyMsg, self)
        }
    }

    impl DummyMsg {
        fn new(body: [u8; 4]) -> DummyMsg {
            let len = size_of::<DummyMsg>() as u16;
            DummyMsg {
                header: MessageHeader::new(len, MessageType::DUMMY2),
                body,
            }
        }
    }

    let (reader, writer) = UnixStream::pair().unwrap();
    let mut sr = ServiceConnection::from_stream("r".to_string(), reader);
    let mut sw = ServiceConnection::from_stream("w".to_string(), writer);

    let body = [2, 4, 6, 8];

    sw.send(DummyMsg::new(body)).await.unwrap();
    let (typ, buf) = sr.recv().await.unwrap();
    assert_eq!(MessageType::from_u16(typ), Some(MessageType::DUMMY2));

    assert_eq!(buf, body);
    ()
}
