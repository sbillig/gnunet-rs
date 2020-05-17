gnunet-rs
=========

This is a fork of [kc1212's gsoc fork](https://github.com/kc1212/gnunet-rs)
of [Andrew Cann's gnunet-rs](https://github.com/canndrew/gnunet-rs).

Short-term goals:

- [x] make it build on a recent nightly rustc (`rustc 1.45.0-nightly (a74d1862d 2020-05-14)`)
- [] make it build on a recent stable rustc
- [] fix warnings
- [] make it work with a recent gnunet release
- [] make the tests pass
- [] remove (most?) uses of `unsafe`
- [] replace gj with futures-rs and async-std or tokio

Tests
-----

Some tests require the gnunet system to be running, and some additional setup.
Do something like the following:
```
gnunet-arm -s
gnunet-identity -c my_cool_name
gnunet-identity -s gns-master -e my_cool_name
```

If you don't run the last command above, some tests will fail with a "no default known" error.
If you *do* run the last command above, some tests will fail with a "Premature EOF" error (TODO).


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
