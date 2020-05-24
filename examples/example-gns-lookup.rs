extern crate gnunet;

fn print_help(executable: String) {
    println!("Usage: {} domain.name.gnu", executable);
}

fn main() {
    let mut args = std::env::args();
    let executable = args.next().unwrap();
    let domain = match args.next() {
        Some(domain) => domain,
        None => {
            println!("Missing domain name");
            print_help(executable);
            return;
        }
    };
    match args.next() {
        Some(x) => {
            println!("Unexpected argument: {}", x);
            print_help(executable);
            return;
        }
        None => (),
    }
}
