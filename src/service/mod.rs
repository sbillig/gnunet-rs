//! Module for communicating with GNUnet services. Implements the parts of the GNUnet IPC protocols
//! that are common to all services.

use byteorder::{BigEndian, ReadBytesExt};
use num::FromPrimitive;
use std::io::{self, Cursor};

use gj::{FulfillerDropped, Promise};
use gjio::{AsyncRead, AsyncWrite, Network, SocketStream};

use crate::configuration::{self, Cfg};
use crate::MessageType;

/// Created by `service::connect`. Used to read messages from a GNUnet service.
#[derive(Clone)]
pub struct ServiceReader {
    /// The underlying socket wrapped by `ServiceReader`. This is a read-only socket.
    pub connection: SocketStream,
}

/// Created by `service::connect`. Used to send messages to a GNUnet service.
#[derive(Clone)]
pub struct ServiceWriter {
    /// The underlying socket wrapped by `ServiceWriter`. This is a write-only socket.
    pub connection: SocketStream,
}

/// Callbacks passed to `ServiceReader::spawn_callback_loop` return a `ProcessMessageResult` to
/// tell the callback loop what action to take next.
#[derive(Copy, Clone)]
pub enum ProcessMessageResult {
    /// Continue talking to the service and passing received messages to the callback.
    Continue,
    /// Attempt to reconnect to the service.
    Reconnect,
    /// Exit the callback loop, shutting down it's thread.
    Shutdown,
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

/// Attempt to connect to the local GNUnet service named `name`.
///
/// eg. `connect(cfg, "arm")` will attempt to connect to the locally-running `gnunet-arm` service
/// using the congfiguration details (eg. socket address, port etc.) in `cfg`.
pub fn connect(
    cfg: &Cfg,
    name: &str,
    network: &Network,
) -> Promise<(ServiceReader, ServiceWriter), ConnectError> {
    let unixpath = pry!(cfg.get_filename(name, "UNIXPATH"));
    let addr = pry!(network.get_unix_address(unixpath.as_path()));
    addr.connect().lift().then(move |in_stream| {
        let out_stream = in_stream.clone();
        Promise::ok((
            ServiceReader {
                connection: in_stream,
            },
            ServiceWriter {
                connection: out_stream,
            },
        ))
    })
}

/// Error that can be generated when attempting to receive data from a service.
#[derive(Debug, Error)]
pub enum ReadMessageError {
    #[error("There was an I/O error communicating with the service. Specifically {source}")]
    Io {
        #[from]
        source: io::Error,
    },
    #[error("The message received from the service was too short. Length was {len} bytes.")]
    ShortMessage { len: u16 },
    #[error("The service disconnected unexpectedly")]
    Disconnected,
    #[error("Promise fulfiller was dropped")]
    FulfillerDropped,
    #[error("Unrecognized message type: {0}")]
    UnrecognizedMessageType(u16),
}

impl FulfillerDropped for ReadMessageError {
    fn fulfiller_dropped() -> ReadMessageError {
        ReadMessageError::FulfillerDropped
    }
}

impl ServiceReader {
    /// Reads a message from the connected socket.
    ///
    /// When using this function multiple times on the same socket the caller needs to make sure the reads are chained together,
    /// otherwise it may return bogus results.
    pub fn read_message(&mut self) -> Promise<(MessageType, Cursor<Vec<u8>>), ReadMessageError> {
        use crate::util::asynch::PromiseReader;
        let mut connection2 = self.connection.clone(); // this is ok we're just bumping Rc count
        self.connection.read_u16().lift().then(move |len| {
            if len < 4 {
                return Promise::err(ReadMessageError::ShortMessage { len: len });
            }
            let rem = len as usize - 2;
            connection2
                .read(vec![0; rem], rem)
                .lift()
                .map(move |(buf, _)| {
                    let mut mr = Cursor::new(buf);
                    let mt = mr.read_u16::<BigEndian>()?;
                    if let Some(mt) = MessageType::from_u16(mt) {
                        Ok((mt, mr))
                    } else {
                        Err(ReadMessageError::UnrecognizedMessageType(mt))
                    }
                })
        })
    }
}

impl ServiceWriter {
    /// Sends a message to the connected socket.
    ///
    /// The message should not have a null-terminated string, otherwise use `send_with_str`.
    pub fn send<T: MessageTrait>(&mut self, message: T) -> Promise<(), io::Error> {
        let x = message.into_slice().to_vec();
        self.connection.write(x).map(|_| Ok(()))
    }

    /// Sends a message with a null-terminated string to the connected socket.
    ///
    /// The caller needs to ensure that the message corresponds to the string, i.e. the message length should add up.
    pub fn send_with_str<T: MessageTrait>(
        &mut self,
        message: T,
        string: &str,
    ) -> Promise<(), io::Error> {
        let mut x = message.into_slice().to_vec();
        x.extend_from_slice(string.as_bytes());
        x.push(0u8.to_be()); // for null-termination of the string
        self.connection.write(x).map(|_| Ok(()))
    }
}

#[repr(C, packed)]
pub struct MessageHeader {
    pub len: u16,
    pub tpe: u16,
}

pub trait MessageTrait {
    fn into_slice(&self) -> &[u8];
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

#[test]
fn test_service() {
    use byteorder::ByteOrder;
    use gj::EventLoop;
    use gjio::EventPort;
    use std::io::Read;
    use std::mem::size_of;

    #[repr(C, packed)]
    struct DummyMsg {
        header: MessageHeader,
        body: u32,
    }

    impl MessageTrait for DummyMsg {
        fn into_slice(&self) -> &[u8] {
            message_to_slice!(DummyMsg, self)
        }
    }

    impl DummyMsg {
        fn new(body: u32) -> DummyMsg {
            let len = size_of::<DummyMsg>() as u16;
            DummyMsg {
                header: MessageHeader {
                    len: len.to_be(),
                    tpe: (MessageType::DUMMY2 as u16).to_be(),
                },
                body: body,
            }
        }
    }

    EventLoop::top_level(move |wait_scope| -> Result<(), ::std::io::Error> {
        let mut event_port = EventPort::new().unwrap();
        let network = event_port.get_network();
        let (reader, writer) = network.new_socket_pair().unwrap();

        let mut sr = ServiceReader { connection: reader };
        let mut sw = ServiceWriter { connection: writer };
        let msg_body: u32 = 42;

        let msg = DummyMsg::new(msg_body);

        sw.send(msg)
            .lift()
            .then(move |()| {
                sr.read_message().map(move |(tpe, mut mr)| {
                    let mut buf = vec![0u8; 4];
                    mr.read_exact(&mut buf)?;
                    assert_eq!(msg_body.to_be(), BigEndian::read_u32(&buf));
                    assert_eq!(MessageType::DUMMY2, tpe);
                    Ok(())
                })
            })
            .wait(wait_scope, &mut event_port)
            .unwrap();

        Ok(())
    })
    .expect("top level");
}
