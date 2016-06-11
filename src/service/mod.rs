//! Module for communicating with GNUnet services. Implements the parts of the GNUnet IPC protocols
//! that are common to all services.

use std::io::{self, Write, Cursor};
use std::thread;
use std::net::Shutdown;
use unix_socket::UnixStream;
use byteorder::{BigEndian, ByteOrder, ReadBytesExt};

use gj::{Promise};
use gjio::{AsyncWrite, AsyncRead, SocketStream, Network};

use configuration::{self, Cfg};
use util::io::ReadUtil;

/*
pub struct Service<'c> {
  //connection: Box<Stream + 'static>,
  //pub connection: Box<UnixStream>,
  pub connection: UnixStream,
  pub cfg: &'c Cfg,
}
*/

/// Created by `service::connect`. Used to read messages from a GNUnet service.
pub struct ServiceReader {
    /// The underlying socket wrapped by `ServiceReader`. This is a read-only socket.
    pub connection: UnixStream, // TODO: should be UnixReader
}

/// Created by `service::connect`. Used to send messages to a GNUnet service.
pub struct ServiceWriter {
    /// The underlying socket wrapped by `ServiceWriter`. This is a write-only socket.
    pub connection: UnixStream, // TODO: should be UnixWriter
}


// TODO better if this is a part of gjio
pub fn read_u16_from_socket(socket: & mut SocketStream) -> Promise<u16, io::Error>{
    socket.read(vec![0;2], 2).then(move |(buf, len)| {
        assert!(len == 2);
        Promise::ok(BigEndian::read_u16(&buf[..]))
    })
}

/// Created by `service::connect_async`. Used to read messages from a GNUnet service.
pub struct ServiceReader_Async {
    /// The underlying socket wrapped by `ServiceReader`. This is a read-only socket.
    pub connection: SocketStream,
}

/// Created by `service::connect_async`. Used to send messages to a GNUnet service.
pub struct ServiceWriter_Async {
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
pub fn connect(cfg: &Cfg, name: &str) -> Result<(ServiceReader, ServiceWriter), ConnectError> {
  let unixpath = try!(cfg.get_filename(name, "UNIXPATH"));

  // TODO: use UnixStream::split() instead when it exists
  let path = unixpath.into_os_string().into_string().unwrap();
  let in_stream = try!(UnixStream::connect(path));
  let out_stream = try!(in_stream.try_clone());


  let r = ServiceReader {
    connection: in_stream,
  };
  let w = ServiceWriter {
    connection: out_stream,
  };
  Ok((r, w))
}

pub fn connect_async(cfg: &Cfg, name: &str, network: &Network) -> Promise<(ServiceReader_Async, ServiceWriter_Async), ConnectError> {
    let unixpath = pry!(cfg.get_filename(name, "UNIXPATH"));
    let addr = pry!(network.get_unix_address(unixpath.as_path()));
    addr.connect()
        .lift()
        .then(move |in_stream| {
            let out_stream = in_stream.clone();
            Promise::ok((ServiceReader_Async{ connection: in_stream },
                         ServiceWriter_Async{ connection: out_stream }))
        })
}

/// Error that can be generated when attempting to receive data from a service.
error_def! ReadMessageError {
  Io { #[from] cause: io::Error } => "There was an I/O error communicating with the service" ("Specifically {}", cause),
  ShortMessage { len: u16 }       => "The message received from the service was too short" ("Length was {} bytes.", len),
  Disconnected                    => "The service disconnected unexpectedly",
}

impl ServiceReader {
  pub fn spawn_callback_loop<F>(mut self, mut cb: F) -> Result<ServiceReadLoop, io::Error>
      where F: FnMut(u16, Cursor<Vec<u8>>) -> ProcessMessageResult,
            F: Send,
            F: 'static
  {
    let reader = try!(self.connection.try_clone());
    let callback_loop = thread::spawn(move || -> ServiceReader {
      //TODO: implement reconnection (currently fails)
      loop {
        let (tpe, mr) = match self.read_message() {
          Ok(x)   => x,
          Err(_)  => return self, // TODO: reconnect
        };
        match cb(tpe, mr) {
          ProcessMessageResult::Continue  => (),
          ProcessMessageResult::Reconnect => return self, //TODO: auto reconnect
          ProcessMessageResult::Shutdown  => return self,
        };
      }
    });
    Ok(ServiceReadLoop {
      reader:        reader,
      _callback_loop: callback_loop,
    })
  }

  pub fn read_message(&mut self) -> Result<(u16, Cursor<Vec<u8>>), ReadMessageError> {
    let len = try!(self.connection.read_u16::<BigEndian>());
    if len < 4 {
      return Err(ReadMessageError::ShortMessage { len: len });
    };
    let v = try!(self.connection.read_exact_alloc(len as usize - 2));
    let mut mr = Cursor::new(v);
    let tpe = try!(mr.read_u16::<BigEndian>());
    Ok((tpe, mr))
  }
}

impl ServiceReader_Async {
    pub fn read_message(&mut self) -> Promise<(u16, Cursor<Vec<u8>>), ReadMessageError> {
        let mut conn =  self.connection.clone(); // TODO is  this ok?
        read_u16_from_socket(& mut conn)
            .lift()
            .then(move |len| {
                if len < 4 {
                    return Promise::err(ReadMessageError::ShortMessage { len: len });
                }
                let rem = len as usize - 2;
                conn.read(vec![0; rem], rem).lift()
            })
            .map(move |(buf, _)| {
                let mut mr = Cursor::new(buf);
                let tpe = try!(mr.read_u16::<BigEndian>());
                Ok((tpe, mr))
            })
    }
}

impl ServiceWriter {
    pub fn send<T: MessageTrait>(& mut self, message: T) -> Result<(), io::Error> {
        self.connection.write_all(message.into_slice())
    }
}

impl ServiceWriter_Async {
    pub fn send<T: MessageTrait>(& mut self, message: T) -> Promise<(), io::Error> {
        let x = message.into_slice().to_vec(); // TODO this makes a copy is it ok?
        self.connection.write(x)
            .map(|_| {
                Ok(())
            })
    }
}

/// A thread that loops, recieving messages from the service and passing them to a callback.
/// Created with `ServiceReader::spawn_callback_loop`.
pub struct ServiceReadLoop {
  reader: UnixStream,
  _callback_loop: thread::JoinHandle<ServiceReader>,
}

impl ServiceReadLoop {
  /*
  fn join(mut self) -> ServiceReader {
    let _ = self.reader.shutdown(Shutdown::Read);
    self.callback_loop.join().unwrap()
  }
  */
}

impl Drop for ServiceReadLoop {
  fn drop(&mut self) {
    let _ = self.reader.shutdown(Shutdown::Read);
    //let _ = self.callback_loop.join();
  }
}

/*
// TODO: why do I need this unsafe bizo?
#[unsafe_destructor]
impl Drop for ServiceReader {
  fn drop(&mut self) {
    // cause the loop task to exit
    let _ = self.connection.close_read();
  }
}
*/

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
