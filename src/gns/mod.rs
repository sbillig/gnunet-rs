use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::mpsc::{channel, Sender, Receiver, TryRecvError};
use std::io::{self, Write, Cursor};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use gj::{Promise};
use gjio::{Network};

use identity;
use ll;
use service::{self, ServiceWriter, ServiceReader, ProcessMessageResult, MessageTrait, MessageHeader};
use EcdsaPublicKey;
use EcdsaPrivateKey;
use Cfg;
pub use self::record::*;

mod record;

/// A handle to a locally-running instance of the GNS daemon.
pub struct GNS {
    service_reader: ServiceReader,
    service_writer: ServiceWriter,
}

/// Options for GNS lookups.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LocalOptions {
  /// Default behaviour. Look in the local cache, then in the DHT.
  Default     = 0,
  /// Do not look in the DHT, keep the request to the local cache.
  NoDHT       = 1,
  /// For domains controlled by our master zone only look in the cache. Otherwise look in the
  /// cache, then in the DHT.
  LocalMaster = 2,
}

/// Possible errors returned by the GNS lookup functions.
error_def! LookupError {
  NameTooLong { name: String }
    => "The domain name was too long" ("The domain name \"{}\" is too long to lookup.", name),
  Io { #[from] cause: io::Error }
    => "There was an I/O error communicating with the service" ("Specifically {}", cause),
}

impl GNS {
    /// Connect to the GNS service.
    ///
    /// Returns either a handle to the GNS service or a `service::ConnectError`. `cfg` contains the
    /// configuration to use to connect to the service.
    pub fn connect(cfg: &Cfg, network: &Network) -> Promise<GNS, service::ConnectError> {
        service::connect(cfg, "gns", network)
            .map(|(sr, sw)| {
                Ok(GNS {
                    service_reader: sr,
                    service_writer: sw,
                })
            })
    }

    fn parse_lookup_result(&self, tpe: u16, reader: Cursor<Vec<u8>>) -> ProcessMessageResult {
        match tpe {
            ll::GNUNET_MESSAGE_TYPE_GNS_LOOKUP_RESULT => {
                let id = match reader.read_u32::<BigEndian>() {
                    Ok(id)  => id,
                    Err(_)  => return ProcessMessageResult::Reconnect,
                };
                let rd_count = match reader.read_u32::<BigEndian>() {
                    Ok(x)   => x,
                    Err(_)  => return ProcessMessageResult::Reconnect,
                };
                println!("WOW rd_count == {}", rd_count);
                for _ in 0..rd_count {
                    let rec = match Record::deserialize(&mut reader) {
                        Ok(r)   => r,
                        Err(_)  => return ProcessMessageResult::Reconnect,
                    };
                    println!("WOW we deserialised it");
                };
            },
            _ => return ProcessMessageResult::Reconnect,
        };
    }

  /// Lookup a GNS record in the given zone.
  ///
  /// If `shorten` is not `None` then the result is added to the given shorten zone. Returns
  /// immediately with a handle that can be queried for results.
  ///
  /// # Example
  ///
  /// ```rust
  /// use gnunet::{Cfg, IdentityService, GNS, gns};
  ///
  /// let config = Cfg::default().unwrap();
  /// let mut ids = IdentityService::connect(&config).unwrap();
  /// let gns_ego = ids.get_default_ego("gns-master").unwrap();
  /// let mut gns = GNS::connect(&config).unwrap();
  /// let mut lh = gns.lookup("gnu.org",
  ///                         &gns_ego.get_public_key(),
  ///                         gns::RecordType::A,
  ///                         gns::LocalOptions::LocalMaster,
  ///                         None).unwrap();
  /// let record = lh.recv();
  /// println!("Got the IPv4 record for gnu.org: {}", record);
  /// ```
  pub fn lookup<'a>(
      &'a mut self,
      name: &str,
      zone: &EcdsaPublicKey,
      record_type: RecordType,
      options: LocalOptions,
      shorten: Option<&EcdsaPrivateKey>
    ) -> Result<LookupHandle<'a>, LookupError> {

    let name_len = name.len();
    if name_len > ll::GNUNET_DNSPARSER_MAX_NAME_LENGTH as usize {
      return Err(LookupError::NameTooLong { name: name.to_string() });
    };

    let id = self.lookup_id;
    self.lookup_id += 1;

    let msg = GnsMessage {
      id: id,
      zone: zone,
      options: options,
      shorten: shorten,
      record_type: record_type,
      name: name,
    };
    let mw = self.service_writer.write_message2(msg);
    let (tx, rx) = channel::<Record>();
    self.lookup_tx.send((id, tx)).unwrap(); // panics if the callback loop has panicked
    try!(mw.send());
    Ok(LookupHandle {
      marker: PhantomData,
      receiver: rx,
    })
  }
}

#[repr(C, packed)]
struct LookupMessage {
    header: MessageHeader,
    id: u32,
    zone: EcdsaPublicKey,
    options: i16, // LocalOptions
    have_key: i16, // 0 or 1
    record_type: i32, // RecordType
    shorten_key: EcdsaPrivateKey,
    // followed by 0-terminated name to look up
}

impl LookupMessage {
    fn new(id: u32,
           zone: EcdsaPublicKey,
           options: LocalOptions,
           shorten: Option<EcdsaPrivateKey>,
           record_type: RecordType,
           name: &str) -> LookupMessage {
        use std::mem;
        let name_len =  name.len();
        let msg_len = (mem::size_of::<LookupMessage>() + name_len + 1).to_u16().unwrap(); // TODO better error handling
        LookupMessage {
            header: MessageHeader {
                len: msg_len.to_be(),
                tpe: ll::GNUNET_MESSAGE_TYPE_GNS_LOOKUP.to_be(),
            },
            id: id.to_be(),
            zone: zone,
            options: (options as i16).unwrap().to_be(),
            have_key: (shorten.is_some() as i16).unwrap().to_be(),
            record_type: (record_type as i32).unwrap().to_be(),
            shorten_key: match shorten {
                Some(x) => x,
                None    => EcdsaPrivateKey{ data: [0u8; 32] },
            }
        }
    }
}

impl MessageTrait for LookupMessage {
    // Note that this does not include the 0-terminated string.
    fn into_slice(&self) -> &[u8] {
        message_to_slice!(LookupMessage, self)
    }
}

/// Errors returned by `gns::lookup`.
error_def! ConnectLookupError {
  Connect { #[from] cause: service::ConnectError }
    => "Failed to connect to the GNS service" ("Reason: {}", cause),
  Lookup { #[from] cause: LookupError }
    => "Failed to perform the lookup." ("Reason: {}", cause),
}

/// Lookup a GNS record in the given zone.
///
/// If `shorten` is not `None` then the result is added to the given shorten zone. This function
/// will block until it returns the first matching record that it can find.
///
/// # Example
///
/// ```rust
/// use gnunet::{Cfg, identity, gns};
///
/// let config = Cfg::default().unwrap();
/// let gns_ego = identity::get_default_ego(&config, "gns-master").unwrap();
/// let record = gns::lookup(&config,
///                          "gnu.org",
///                          &gns_ego.get_public_key(),
///                          gns::RecordType::A,
///                          gns::LocalOptions::LocalMaster,
///                          None).unwrap();
/// println!("Got the IPv4 record for gnu.org: {}", record);
/// ```
///
/// # Note
///
/// This is a convenience function that connects to the GNS service, performs the lookup, retrieves
/// one result, then disconects. If you are performing multiple lookups this function should be
/// avoided and `GNS::lookup_in_zone` used instead.
pub fn lookup(
    cfg: &Cfg,
    name: &str,
    zone: &EcdsaPublicKey,
    record_type: RecordType,
    options: LocalOptions,
    shorten: Option<&EcdsaPrivateKey>) -> Result<Record, ConnectLookupError> {
  println!("connecting to GNS");
  let mut gns = try!(GNS::connect(cfg));
  println!("connected to GNS");
  let mut h = try!(gns.lookup(name, zone, record_type, options, shorten));
  println!("doing lookup");
  Ok(h.recv())
}

/// Errors returned by `gns::lookup_in_master`.
error_def! ConnectLookupInMasterError {
  GnsLookup { #[from] cause: ConnectLookupError }
    => "Failed to connect to the GNS service and perform the lookup" ("Reason: {}", cause),
  IdentityGetDefaultEgo { #[from] cause: identity::ConnectGetDefaultEgoError }
    => "Failed to retrieve the default identity for gns-master from the identity service" ("Reason: {}", cause),
}

/// Lookup a GNS record in the master zone.
///
/// If `shorten` is not `None` then the result is added to the given shorten zone. This function
/// will block until it returns the first matching record that it can find.
///
/// # Example
///
/// ```rust
/// use gnunet::{Cfg, gns};
///
/// println!("in test lookup_in_master");
///
/// let config = Cfg::default().unwrap();
/// let record = gns::lookup_in_master(&config, "gnu.org", gns::RecordType::A, None).unwrap();
/// println!("Got the IPv4 record for gnu.org: {}", record);
/// ```
///
/// # Note
///
/// This is a convenience function that connects to the identity service, fetches the default ego
/// for gns-master, then connects to the GNS service, performs the lookup, retrieves one result,
/// then disconnects from everything. If you are performing lots of lookups this function should be
/// avoided and `GNS::lookup_in_zone` used instead.
pub fn lookup_in_master(
    cfg: &Cfg,
    name: &str,
    record_type: RecordType,
    shorten: Option<&EcdsaPrivateKey>) -> Result<Record, ConnectLookupInMasterError> {
  println!("Getting default ego");
  let ego = try!(identity::get_default_ego(cfg, "gns-master"));
  println!("got default ego: {}", ego);
  let pk = ego.get_public_key();
  let mut it = name.split('.');
  let opt = match (it.next(), it.next(), it.next()) {
    (Some(_), Some("gnu"), None)  => LocalOptions::NoDHT,
    _                             => LocalOptions::LocalMaster,
  };
  println!("doing lookup");
  let ret = try!(lookup(cfg, name, &pk, record_type, opt, shorten));
  println!("lookup succeeded");
  Ok(ret)
}

/// A handle returned by `GNS::lookup`.
///
/// Used to retrieve the results of a lookup.
pub struct LookupHandle<'a> {
  marker: PhantomData<&'a GNS>,
  receiver: Receiver<Record>,
}

impl<'a> LookupHandle<'a> {
  /// Receive a single result from a lookup.
  ///
  /// Blocks until a result is available. This function can be called multiple times on a handle to
  /// receive multiple results.
  pub fn recv(&mut self) -> Record {
    // unwrap is safe because the LookupHandle cannot outlive the remote sender.
    self.receiver.recv().unwrap()
  }
}

