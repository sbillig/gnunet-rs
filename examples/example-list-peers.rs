extern crate gnunet;
extern crate gjio;
extern crate gj;

use gj::{EventLoop, Promise};
use gjio::{AsyncRead, AsyncWrite, BufferPrefix, SocketStream, EventPort, Network, Timer};
use std::time::Duration;
use std::io::{Error, ErrorKind};

fn main() {
    let config = gnunet::Cfg::default().unwrap();

    // example to get all peers
    let peers = gnunet::iterate_peers(&config).unwrap();
    for result in peers {
        let (peerinfo, hello) = result.unwrap();
        println!("Peer: {}", peerinfo);
        if let Some(hello) = hello {
            println!("Hello: {}", hello);
        };
        println!("");
    };


    // example to get a single peer
    let pk_string = "DPQIBOOJV8QBS3FGJ6B0K5NTSQ9SULV45H5KCR4HU7PQ64N8Q9F0".to_string();
    let (peer, _) = gnunet::get_peer(&config, pk_string).unwrap();
    match peer {
        Some(p) => println!("Peer found: {}", p),
        None    => println!("peer not found"),
    }


    let local_id = gnunet::self_id(&config).unwrap();
    println!("Our id is: {}", local_id);

    println!("");
    println!("Async tests below.");
    // async tests
    EventLoop::top_level(|wait_scope| -> Result<(), ::std::io::Error> {
        let mut event_port: EventPort = gjio::EventPort::new().unwrap();
        let network: Network = event_port.get_network();

        // test peerinfo
        let mut peer_async = gnunet::iterate_peers_async(&config, &network).wait(wait_scope, &mut event_port).unwrap();
        let mut peer = peer_async.get_next_peer().wait(wait_scope, &mut event_port).unwrap();
        while peer.is_some() {
            let (peerinfo, _) = peer.unwrap();
            println!("Peer: {}\n", peerinfo);
            peer = peer_async.get_next_peer().wait(wait_scope, &mut event_port).unwrap();
        }

        // test hello, with timeout
        let local_id_promise = event_port.get_timer()
            .timeout_after(Duration::from_secs(1),
                           gnunet::self_id_async(&config, &network).map_err(|_| {
                               ::std::thread::sleep(Duration::from_secs(2));
                               Error::new(ErrorKind::Other, "oh no!") }));
        let local_id = local_id_promise.wait(wait_scope, & mut event_port).unwrap();
        println!("Our id is: {}", local_id);

        // multiple hellos
        let promise1 = gnunet::self_id_async(&config, &network);
        let promise2 = gnunet::self_id_async(&config, &network);
        let promise3 = gnunet::self_id_async(&config, &network);
        let ids = Promise::all(vec![promise1, promise2, promise3].into_iter()).wait(wait_scope, &mut event_port);
        Ok(())
    }).expect("top level");
}


