//! Module for communicating with GNUnet services. Implements the parts of the GNUnet IPC protocols
//! that are common to all services.

use crate::util::serial::*;
use crate::util::{config, Config, MessageHeader, MessageOut, MessageOutCompound};
use async_std::io;
use async_std::os::unix::net::UnixStream;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use std::fmt;
use tracing::{debug, instrument};

/// Attempt to connect to the local GNUnet service named `name`.
///
/// eg. `connect(&cfg, "arm")` will attempt to connect to the locally-running `gnunet-arm` service
/// using the congfiguration details (eg. socket address, port etc.) in `cfg`.
pub async fn connect(cfg: &Config, name: &str) -> Result<Connection, ConnectError> {
    let path = cfg.get_filename(name, "UNIXPATH")?;
    let sock = UnixStream::connect(&path).await?;

    // see gnunet/src/util/client.c::start_connect
    // TODO: tcp

    Ok(Connection {
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
        source: config::ConfigGetFilenameError,
    },
    #[error("There was an I/O error communicating with the service. Specifically {source}")]
    Io {
        #[from]
        source: io::Error,
    },
}

/// Created by `service::connect`. Used to read messages from a GNUnet service.
pub struct Connection {
    name: String,
    inner: UnixStream,
}

impl Connection {
    /// Sends a message to the connected socket.
    ///
    /// The message should not have a null-terminated string, otherwise use `send_with_str`.
    pub async fn send<M: MessageOut>(&mut self, msg: M) -> Result<(), io::Error> {
        self.inner.write_all(&msg.as_bytes().as_ref()).await
    }

    pub async fn send_compound<M: MessageOutCompound>(&mut self, msg: M) -> Result<(), io::Error> {
        for chunk in msg.as_byte_chunks() {
            self.inner.write_all(chunk.as_ref()).await?
        }
        Ok(())
    }

    /// Returns `(header, buffer)`, where `buffer` contains entire message payload
    /// (including the header), for ease of deserializing message structs.
    #[instrument]
    pub async fn recv(&mut self) -> Result<(u16, Buffer), io::Error> {
        let mut buf = Buffer::default();
        buf.resize(4, 0u8);

        let head: MessageHeader = {
            let mut head_bytes = &mut buf[0..4];
            self.inner.read_exact(&mut head_bytes).await?;
            *cast(head_bytes)
        };

        debug!(
            typ = head.msg_type_u16(),
            len = head.length(),
            "type: {:?}",
            head.msg_type(),
        );

        if head.length() > 4 {
            buf.resize(head.length() as usize, 0u8);
            let rest = &mut buf[4..];
            self.inner.read_exact(rest).await?;
        }

        Ok((head.msg_type_u16(), buf))
    }

    pub fn from_stream(name: String, inner: UnixStream) -> Self {
        Connection { name, inner }
    }
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("name", &self.name)
            .finish()
    }
}

#[async_std::test]
async fn test_service() {
    use crate::util::serial::*;
    use crate::util::{expect, MessageHeader, MessageIn, MessageType};
    use async_std::os::unix::net::UnixStream;
    use std::mem::size_of;

    #[derive(AsBytes, FromBytes, Copy, Clone, PartialEq, Debug)]
    #[repr(C)]
    struct DummyMsg {
        header: MessageHeader,
        body: [u8; 4],
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

    impl<'a> MessageIn<'a> for DummyMsg {
        fn msg_type() -> MessageType {
            MessageType::DUMMY2
        }
        fn from_bytes(b: &'a [u8]) -> Option<DummyMsg> {
            try_cast(b).copied()
        }
    }

    let (reader, writer) = UnixStream::pair().unwrap();
    let mut sr = Connection::from_stream("r".to_string(), reader);
    let mut sw = Connection::from_stream("w".to_string(), writer);

    let body = [2, 4, 6, 8];
    let outmsg = DummyMsg::new(body);
    sw.send(&outmsg).await.unwrap();
    let (typ, buf) = sr.recv().await.unwrap();
    assert_eq!(MessageType::from_u16(typ), Some(MessageType::DUMMY2));

    let inmsg = expect::<DummyMsg>(typ, &buf).unwrap();
    assert_eq!(&inmsg, &outmsg);
}
