extern crate gnunet;
use gnunet::util::async;
use std::rc::Rc;

fn main() {
    async::EventLoop::top_level(|wait_scope| -> Result<(), ::std::io::Error> {
        let config = gnunet::Cfg::default().unwrap();
        let mut event_port = async::EventPort::new().unwrap();
        let network = event_port.get_network();

        // identity example
        let ego = gnunet::get_default_ego(&config, Rc::new("gns-master".to_string()), &network)
            .wait(wait_scope, &mut event_port)
            .unwrap();
        println!("{}", ego);
        Ok(())
    })
    .expect("top level");
}
