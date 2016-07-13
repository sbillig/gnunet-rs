extern crate gnunet;
extern crate gjio;
extern crate gj;

use gj::{EventLoop};
use gjio::{EventPort, Network};

fn print_help(executable: String) {
    println!("Usage: {} domain.name.gnu", executable);
}

fn main() {
    EventLoop::top_level(|wait_scope| -> Result<(), ::std::io::Error> {
        let config = gnunet::Cfg::default().unwrap();
        let mut event_port: EventPort = gjio::EventPort::new().unwrap();
        let network: Network = event_port.get_network();

        // identity example
        match gnunet::identity::get_default_ego(&config, "gns-master", &network).wait(wait_scope, &mut event_port) {
            Ok(ego) => println!("{}", ego),
            Err(e)  => println!("{}", e),
        }
        Ok(())
    }).expect("top level");
    /*
    let mut args = std::env::args();
    let executable = args.next().unwrap();
    let domain     = match args.next() {
        Some(domain)  => domain,
        None          => {
            println!("Missing domain name");
            print_help(executable);
            return;
        },
    };
    match args.next() {
        Some(x) => {
            println!("Unexpected argument: {}", x);
            print_help(executable);
            return;
        },
        None  => (),
    }
    let config = gnunet::Cfg::default().unwrap();
    let record = gnunet::gns::lookup_in_master(&config, &domain[..], gnunet::gns::RecordType::A, None).unwrap();
    println!("\t{}", record);
    */
}

