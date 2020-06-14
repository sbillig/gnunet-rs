use std::io;

use crate::service;
use crate::util::{Config, PeerIdentity};

pub mod msg;
use msg::*;

pub struct Client {
    conn: service::Connection,
    next_id: u32,
}

pub struct Channel {
    id: ChannelId,
}

impl Client {
    pub async fn connect(
        cfg: &Config,
        _listen_ports: Vec<u32>,
    ) -> Result<Client, service::ConnectError> {
        let conn = service::connect(cfg, "cadet").await?;
        Ok(Client { conn, next_id: 0 })
    }

    // TODO: incoming message loop
    // {
    //   let msg_length: u16 = 4 + 4 * listen_ports.len() as u16; // TODO: check for overflow
    //   let mut mw = service_writer.write_message(msg_length, MessageType::CADET_LOCAL_CONNECT);
    //   for port in listen_ports.iter() {
    //     mw.write_u32::<BigEndian>(*port).unwrap();
    //   }
    //   mw.send()?;
    // }

    pub async fn connect_to_peer(
        &mut self,
        peer: &PeerIdentity,
        port: u32,
        opt: ChannelOptions,
    ) -> Result<Channel, io::Error> {
        let id = self.next_channel_id();
        let msg = LocalChannelCreate::new(id, *peer, port, opt);
        self.conn.send(&msg).await?;
        // TODO: service response?
        Ok(Channel { id })
    }

    fn next_channel_id(&mut self) -> ChannelId {
        let id = ChannelId(self.next_id);
        self.next_id += 1;
        id
    }
}
