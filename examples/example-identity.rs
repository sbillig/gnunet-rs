extern crate gnunet;
use gnunet::util::async;

fn main() {
    async::EventLoop::top_level(|wait_scope| -> Result<(), ::std::io::Error> {
        let config = gnunet::Cfg::default().unwrap();
        let mut event_port = async::new_event_port();
        let network = event_port.get_network();

        // identity example
        match gnunet::get_default_ego(&config, "gns-master", &network).wait(wait_scope, &mut event_port) {
            Ok(ego) => println!("{}", ego),
            Err(e)  => println!("{}", e),
        }
        Ok(())
    }).expect("top level");
}

