use std::io::{self, Cursor};
use byteorder::{BigEndian, WriteBytesExt};

use ll;
use Config;
use PeerIdentity;
use service::{self, ServiceReadLoop, ServiceWriter, ProcessMessageResult};

pub struct ChannelId(u32);

pub struct ChannelOptions {
  pub no_buffer:    bool,
  pub reliable:     bool,
  pub out_of_order: bool,
}

impl ChannelOptions {
  /// Encode a `ChannelOptions` as a u32 for transmission across the network.
  pub fn as_u32(&self) -> u32 {
    let mut opt_code = 0;
    if self.no_buffer    { opt_code |= 1 };
    if self.reliable     { opt_code |= 2 };
    if self.out_of_order { opt_code |= 4 };
    opt_code
  }
}

pub struct Cadet {
  service_writer: ServiceWriter,
  _callback_loop: ServiceReadLoop,
  next_channel_id: u32,
}

pub struct Channel {
  id: u32,
}

impl Cadet {
  pub fn init(cfg: &Config, listen_ports: Vec<u32>) -> Result<Cadet, service::ConnectError> {
    let (service_reader, mut service_writer) = service::connect(cfg, "cadet")?;
    let callback_loop = try!(service_reader.spawn_callback_loop(move |tpe: u16, mut reader: Cursor<Vec<u8>>| -> ProcessMessageResult {
      println!("Got message!: tpe == {}", tpe);
      ProcessMessageResult::Continue
    }));
    {
      let msg_length: u16 = 4 + 4 * listen_ports.len() as u16; // TODO: check for overflow
      let mut mw = service_writer.write_message(msg_length, MessageType::CADET_LOCAL_CONNECT);
      for port in listen_ports.iter() {
        mw.write_u32::<BigEndian>(*port).unwrap();
      }
      mw.send()?;
    };
    Ok(Cadet {
      service_writer: service_writer,
      _callback_loop: callback_loop,
      next_channel_id: 0x80000000,
    })
  }

  pub fn connect(&mut self, peer: &PeerIdentity, port: u32, opt: ChannelOptions) -> Result<Channel, io::Error> {
    let msg_length = 4 + 4 + 32 + 4 + 4;
    let mut mw = self.service_writer.write_message(msg_length, MessageType::CADET_LOCAL_CHANNEL_CREATE);
    let id = self.next_channel_id;
    self.next_channel_id += 1;
    mw.write_u32::<BigEndian>(id).unwrap();
    peer.serialize(&mut mw).unwrap();
    mw.write_u32::<BigEndian>(port).unwrap();
    mw.write_u32::<BigEndian>(opt.as_u32()).unwrap();
    mw.send()?;
    Ok(Channel {
      id: id,
    })
  }
}
