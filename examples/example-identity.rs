extern crate gnunet;
extern crate gjio;
extern crate gj;

use gj::{EventLoop};
use gjio::{EventPort, Network};

fn main() {
    EventLoop::top_level(|wait_scope| -> Result<(), ::std::io::Error> {
        let config = gnunet::Cfg::default().unwrap();
        let mut event_port: EventPort = EventPort::new().unwrap();
        let network: Network = event_port.get_network();

        // identity example
        match gnunet::identity::get_default_ego(&config, "gns-master", &network).wait(wait_scope, &mut event_port) {
            Ok(ego) => println!("{}", ego),
            Err(e)  => println!("{}", e),
        }
        Ok(())
    }).expect("top level");
}

