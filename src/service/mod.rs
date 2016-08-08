//! Module for communicating with GNUnet services. Implements the parts of the GNUnet IPC protocols
//! that are common to all services.

use std::io::{self, Cursor};
use byteorder::{BigEndian, ReadBytesExt};

use gj::{Promise, FulfillerDropped};
use gjio::{AsyncWrite, AsyncRead, SocketStream, Network};

use configuration::{self, Cfg};

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
error_def! ConnectError {
    NotConfigured { #[from] cause: configuration::CfgGetFilenameError }
        => "The configuration does not describe how to connect to the service"
            ("Config does not contain an entry for UNIXPATH in the service's section: {}", cause),
    Io { #[from] cause: io::Error }
        => "There was an I/O error communicating with the service" ("Specifically {}", cause),
}

/// Attempt to connect to the local GNUnet service named `name`.
///
/// eg. `connect(cfg, "arm")` will attempt to connect to the locally-running `gnunet-arm` service
/// using the congfiguration details (eg. socket address, port etc.) in `cfg`.
pub fn connect(cfg: &Cfg, name: &str, network: &Network)
                     -> Promise<(ServiceReader, ServiceWriter), ConnectError> {
    let unixpath = pry!(cfg.get_filename(name, "UNIXPATH"));
    let addr = pry!(network.get_unix_address(unixpath.as_path()));
    addr.connect()
        .lift()
        .then(move |in_stream| {
            let out_stream = in_stream.clone();
            Promise::ok((ServiceReader{ connection: in_stream },
                         ServiceWriter{ connection: out_stream }))
        })
}

/// Error that can be generated when attempting to receive data from a service.
error_def! ReadMessageError {
    Io { #[from] cause: io::Error } => "There was an I/O error communicating with the service" ("Specifically {}", cause),
    ShortMessage { len: u16 }       => "The message received from the service was too short" ("Length was {} bytes.", len),
    Disconnected                    => "The service disconnected unexpectedly",
    FulfillerDropped => "Promise fulfiller was dropped",
}

impl FulfillerDropped for ReadMessageError {
    fn fulfiller_dropped() -> ReadMessageError {
        ReadMessageError::FulfillerDropped
    }
}

impl ServiceReader {
    pub fn read_message(&mut self) -> Promise<(u16, Cursor<Vec<u8>>), ReadMessageError> {
        use util::async::PromiseReader;
        let mut connection2 =  self.connection.clone(); // this is ok we're just bumping Rc count
        self.connection.read_u16()
            .lift()
            .then(move |len| {
                if len < 4 {
                    return Promise::err(ReadMessageError::ShortMessage { len: len });
                }
                let rem = len as usize - 2;
                connection2.read(vec![0; rem], rem).lift()
            })
            .map(move |(buf, _)| {
                let mut mr = Cursor::new(buf);
                let tpe = try!(mr.read_u16::<BigEndian>());
                Ok((tpe, mr))
            })
    }

    // the callback `cb` should not block
    pub fn spawn_callback_loop<F>(&mut self, mut cb: F) -> Promise<(), ReadMessageError>
        where F: FnMut(u16, Cursor<Vec<u8>>) -> ProcessMessageResult,
              F: 'static
    {
        let mut sr = self.clone();
        self.read_message().then(move |(tpe, mr)| {
            match cb(tpe, mr) {
                ProcessMessageResult::Continue  => sr.spawn_callback_loop(cb),
                ProcessMessageResult::Reconnect => Promise::ok(()), //TODO: auto reconnect
                ProcessMessageResult::Shutdown => Promise::ok(()),
            }
        })
    }
}

impl ServiceWriter {
    pub fn send<T: MessageTrait>(&mut self, message: T) -> Promise<(), io::Error> {
        let x = message.into_slice().to_vec();
        self.connection.write(x)
            .map(|_| {
                Ok(())
            })
    }

    pub fn send_with_str<T: MessageTrait>(&mut self, message: T, string: &str) -> Promise<(), io::Error> {
        let mut x = message.into_slice().to_vec();
        x.extend_from_slice(string.as_bytes());
        x.push(0u8.to_be()); // for null-termination of the string
        self.connection.write(x)
        .map(|_| {
            Ok(())
        })
    }

    pub fn write_buf<T>(&mut self, buf: T) -> Promise<(), io::Error> where T: AsRef<[u8]> + 'static {
        self.connection.write(buf)
            .map(|_| {
                Ok(())
            })
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
        use std::slice;
        use std::mem;
        let p: *const $t = $i;
        let p: *const u8 = p as *const u8;
        let res : &[u8] = unsafe {
            slice::from_raw_parts(p, mem::size_of::<$t>())
        };
        res
    }}
}
