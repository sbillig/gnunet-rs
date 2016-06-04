extern crate gnunet;

fn main() {
    let config = gnunet::Cfg::default().unwrap();
    let peers = gnunet::iterate_peers(&config).unwrap();
    for result in peers {
        let (peerinfo, hello) = result.unwrap();
        println!("Peer: {}", peerinfo);
        if let Some(hello) = hello {
            println!("Hello: {}", hello);
        };
        println!("");
    };


    // TODO list_peer shouldn't return an iterator
    let pk_string = "DPQIBOOJV8QBS3FGJ6B0K5NTSQ9SULV45H5KCR4HU7PQ64N8Q9F0".to_string();
    let single_peer = gnunet::list_peer(&config, pk_string).unwrap();
    for result in single_peer {
        println!("Showing a single peer");
        let (peerinfo, hello) = result.unwrap();
        println!("Peer: {}", peerinfo);
        println!("");
    };

    let local_id = gnunet::self_id(&config).unwrap();
    println!("Our id is: {}", local_id);
}

