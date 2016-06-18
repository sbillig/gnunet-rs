extern crate gnunet;
extern crate gjio;
extern crate gj;

use std::io::{Error, ErrorKind};
use gj::{EventLoop, Promise};
use gjio::{EventPort, Network};

fn cancel<T, E>(p: Promise<T, E>) -> Promise<T, E>
    where E: From<Error>
{
    let err = Promise::err(Error::new(ErrorKind::Interrupted, "Promise cancelled"));
    err.lift().exclusive_join(p)
}

fn main() {
    EventLoop::top_level(|wait_scope| -> Result<(), ::std::io::Error> {
        let config = gnunet::Cfg::default().unwrap();
        let mut event_port: EventPort = gjio::EventPort::new().unwrap();
        let network: Network = event_port.get_network();

        // example to get all peers
        let mut peers = gnunet::iterate_peers(&config, &network).wait(wait_scope, &mut event_port).unwrap();
        let mut peer = peers.iterate().wait(wait_scope, &mut event_port).unwrap();
        while peer.is_some() {
            let (peerinfo, _) = peer.unwrap();
            println!("Peer: {}\n", peerinfo);
            peer = peers.iterate().wait(wait_scope, &mut event_port).unwrap();
        }

        // example to get a single peer
        let pk_string = "DPQIBOOJV8QBS3FGJ6B0K5NTSQ9SULV45H5KCR4HU7PQ64N8Q9F0".to_string();
        let (peer, _) = gnunet::get_peer(&config, &network, pk_string).wait(wait_scope, &mut event_port).unwrap();
        match peer {
            Some(p) => println!("Peer found: {}", p),
            None    => println!("peer not found"),
        }

        // example to get hello id
        let local_id = gnunet::self_id(&config, &network).wait(wait_scope, &mut event_port).unwrap();
        println!("Our id is: {}", local_id);

        // cancellation example
        match cancel(gnunet::self_id(&config, &network)).wait(wait_scope, &mut event_port) {
            Err(e) => println!("Error: {}", e),
            Ok(_)  => assert!(false),
        }

        Ok(())
    }).expect("top level");
}
