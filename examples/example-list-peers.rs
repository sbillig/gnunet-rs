extern crate gnunet;
use gnunet::util::async;

fn main() {
    async::EventLoop::top_level(|wait_scope| -> Result<(), ::std::io::Error> {
        let config = gnunet::Cfg::default().unwrap();
        let mut event_port = async::EventPort::new().unwrap();
        let network = event_port.get_network();

        // example to iterate over all peers
        {
            // peers_iter needs to go out of scope before using `&mut event_port` again
            let peers_iter = gnunet::get_peers_iterator(&config, &network, wait_scope, &mut event_port).unwrap();
            for peer in peers_iter {
                let (peerinfo, _) = peer.unwrap();
                println!("Peer: {}\n", peerinfo);
            }
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
        match async::cancel(gnunet::self_id(&config, &network)).wait(wait_scope, &mut event_port) {
            Err(e) => println!("Error: {}", e),
            Ok(_)  => assert!(false),
        }

        Ok(())
    }).expect("top level");
}
