extern crate gnunet;
extern crate gjio;
extern crate gj;

use gnunet::util::async;

fn print_help(executable: String) {
    println!("Usage: {} domain.name.gnu", executable);
}

fn main() {
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
    */

    async::EventLoop::top_level(move |wait_scope| -> Result<(), ::std::io::Error> {
        let config = gnunet::Cfg::default().unwrap();
        let mut event_port = async::EventPort::new().unwrap();
        let network = event_port.get_network();

        let record_promise = gnunet::gns::lookup_in_master(&config, &network, "gnu.org", gnunet::gns::RecordType::A, None);
        match record_promise.wait(wait_scope, &mut event_port) {
            Ok(r)  => { println!("record: {:?}", r) },
            Err(e) => { println!("error:  {}", e) },
        }
        Ok(())
    }).expect("top level");
}

