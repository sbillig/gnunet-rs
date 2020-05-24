gnunet-rs
=========

This is a fork of [kc1212's gsoc fork](https://github.com/kc1212/gnunet-rs)
of [Andrew Cann's gnunet-rs](https://github.com/canndrew/gnunet-rs).

Short-term goals:

- [x] make it build on a recent rustc (using 1.43.1)
- [x] fix warnings
- [ ] make it work with a recent gnunet release
- [ ] make the tests pass
- [ ] remove (most?) uses of `unsafe`
- [ ] update dependencies
- [x] replace gj with futures-rs and async-std
- [ ] use gnunet's testing framework to launch test peer(s)

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
