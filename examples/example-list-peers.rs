extern crate gnunet;
extern crate gjio;
extern crate gj;

use gj::{EventLoop, Promise};
use gjio::{AsyncRead, AsyncWrite, BufferPrefix, SocketStream, EventPort, Network};

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

    // async tests
    EventLoop::top_level(|wait_scope| -> Result<(), ::std::io::Error> {
        let mut event_port: EventPort = gjio::EventPort::new().unwrap();
        let network: Network = event_port.get_network();

        // test peerinfo
        let mut ps = gnunet::iterate_peers_async(&config, &network).wait(wait_scope, & mut event_port).unwrap();
        let mut p = ps.my_next(wait_scope, & mut event_port);
        while p.is_some() {
            let (peerinfo, _) = p.unwrap().unwrap();
            println!("Peer: {}\n", peerinfo);
            p = ps.my_next(wait_scope, & mut event_port);
        }

        // test hello
        let local_id_promise = gnunet::self_id_async(&config, &network);
        let local_id = local_id_promise.wait(wait_scope, & mut event_port).unwrap();
        println!("Our id is: {}", local_id);
        Ok(())
    }).expect("top level");
}


