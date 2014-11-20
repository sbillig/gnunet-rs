extern crate gnunet;

use std::os;

use gnunet::gns;

fn main() {
  let args = os::args();
  if args.len() != 2 {
    println!("Usage: example-gns-lookup domain.name.gnu");
    return;
  };
  match gns::lookup_in_master(None, args[1].as_slice(), gns::A, None) {
    Ok(r)   => println!("\t{}", r),
    Err(e)  => println!("Error: {}", e),
  };
}

