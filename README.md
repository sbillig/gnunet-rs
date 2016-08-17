gnunet-rs
=========

Google Summer of Code
---------------------
This branch (gsoc) is kept as a reference for the work I did for GSoC 2016 with the GNU organisation.
All the working features were converted to make use asynchronous IO during the GSoC working period.
My GSoC page is [here](https://summerofcode.withgoogle.com/projects/#6454361462931456).
I made two blog posts regarding the project - [mid-term](https://gnunet.org/node/2624), [final-term](https://gnunet.org/node/2629).

The project builds as of `rustc 1.12.0-nightly (080e0e072 2016-08-08)`.
Tests should pass when a GNUnet peer is running on the local macahine.
Run examples with the `--example` flag, for example `cargo run --example example-gns-lookup gnu.org`.

GNUnet bindings for Rust.
-------------------------

*Note:* This library is for interacting with a locally running GNUnet peer. It
does not implement a peer itself. It is also FAR from complete. Only a few
rudimentry features are implemented. You cannot, for example, use this for
peer-to-peer communication (yet).

Features implemented so far:

  * Parsing GNUnet config files.
  * Retrieving peer info from the peerinfo service.
  * Performing GNS lookups.
  * Performing identity ego lookups.

Next on the list:

  * DHT bindings.
  * Cadet (peer-to-peer) bindings.
  * Datastore bindings.

See http://canndrew.org/rust-doc/gnunet for documentation.
See examples directory for example code.
Feedback and pull requests are encouraged!

