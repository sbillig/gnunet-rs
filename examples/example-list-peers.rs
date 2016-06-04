extern crate gnunet;

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
}

