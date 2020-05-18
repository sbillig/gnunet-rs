//! Module for connecting to and querying the GNUnet GNS service.

use byteorder::{BigEndian, ReadBytesExt};
use gj::Promise;
use gjio::Network;
use num::ToPrimitive;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{self, Cursor};
use std::rc::Rc;
use thiserror::Error;

pub use self::record::*;
use crate::service::{
    self, MessageHeader, MessageTrait, ReadMessageError, ServiceReader, ServiceWriter,
};
use crate::{identity, ll, Cfg, EcdsaPrivateKey, EcdsaPublicKey, MessageType};

mod record;

/// A handle to a locally-running instance of the GNS daemon.
pub struct GNS {
    service_reader: ServiceReader,
    service_writer: ServiceWriter,
    lookup_id: u32,
    results_table: Rc<RefCell<HashMap<u32, Vec<Record>>>>,
    read_queue: Rc<RefCell<Option<Promise<(), ()>>>>,
}

/// Options for GNS lookups.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LocalOptions {
    /// Default behaviour. Look in the local cache, then in the DHT.
    Default = 0,
    /// Do not look in the DHT, keep the request to the local cache.
    NoDHT = 1,
    /// For domains controlled by our master zone only look in the cache. Otherwise look in the
    /// cache, then in the DHT.
    LocalMaster = 2,
}

/// Possible errors returned by the GNS lookup functions.
#[derive(Debug, Error)]
pub enum LookupError {
    #[error("The received message type '{tpe:?}' is invalid.")]
    InvalidType { tpe: MessageType },
    #[error("The domain name '{name}' is too long to lookup.")]
    NameTooLong { name: String },
    #[error("There was an I/O error communicating with the service. Specifically {source}")]
    Io {
        #[from]
        source: io::Error,
    },
    #[error("Failed to receive the response from the GNS service. Reason: {source}")]
    ReadMessage {
        #[from]
        source: ReadMessageError,
    },
}

impl GNS {
    /// Connect to the GNS service.
    ///
    /// Returns either a promise to the GNS service or a `service::ConnectError`. `cfg` contains the
    /// configuration to use to connect to the service.
    pub fn connect(cfg: &Cfg, network: &Network) -> Promise<GNS, service::ConnectError> {
        let table = Rc::new(RefCell::new(HashMap::new()));
        service::connect(cfg, "gns", network)
            .lift()
            .map(move |(sr, sw)| {
                Ok(GNS {
                    service_reader: sr,
                    service_writer: sw,
                    lookup_id: 0,
                    results_table: table,
                    read_queue: Rc::new(RefCell::new(None)),
                })
            })
    }

    /// Lookup a vector of GNS records.
    /// A promise of the result is returned.
    ///
    /// If `shorten` is not `None` then the result is added to the given shorten zone.
    ///
    /// # Example
    ///
    /// ```rust
    /// use gnunet::{Cfg, identity, gns, GNS};
    /// use gnunet::util::asynch;
    ///
    /// let config = Cfg::default().unwrap();
    /// let mut event_port = asynch::EventPort::new().unwrap();
    /// let network = event_port.get_network();
    /// let gns_master = ::std::rc::Rc::new("gns-master".to_string());
    ///
    /// asynch::EventLoop::top_level(|wait_scope| -> Result<(), ::std::io::Error> {
    ///     let ego = identity::get_default_ego(&config, gns_master, &network).wait(wait_scope, &mut event_port).unwrap();
    ///     let pk = ego.get_public_key();
    ///     let mut gns = GNS::connect(&config, &network).wait(wait_scope, &mut event_port).unwrap();
    ///     let promises = vec!["gnu.org", "gnunet.org", "freebsd.org"].into_iter().map(|d| {
    ///         gns.lookup(::std::rc::Rc::new(d.to_string()),
    ///                    pk,
    ///                    gns::RecordType::A,
    ///                    gns::LocalOptions::LocalMaster,
    ///                    None)
    ///     });
    ///     let ips = asynch::Promise::all(promises).wait(wait_scope, &mut event_port).unwrap();
    ///     println!("{:?}", ips);
    ///     Ok(())
    /// }).expect("top_level");
    /// ```
    pub fn lookup(
        &mut self,
        name: Rc<String>,
        zone: EcdsaPublicKey,
        record_type: RecordType,
        options: LocalOptions,
        shorten: Option<EcdsaPrivateKey>,
    ) -> Promise<Vec<Record>, LookupError> {
        let id = self.lookup_id;
        self.lookup_id += 1;
        let msg = pry!(LookupMessage::new(
            id,
            zone,
            options,
            shorten,
            record_type,
            &name
        ));
        let mut sr = self.service_reader.clone();
        let map = self.results_table.clone();
        let read_queue = self.read_queue.clone();

        self.service_writer
            .send_with_str(msg, &name)
            .lift()
            .then(move |_| {
                let result = map.borrow_mut().remove(&id);
                match result {
                    // first check whether we already have the result
                    Some(x) => Promise::ok(x),

                    // if there are no results then add task to the read queue
                    None => {
                        let maybe_queue = read_queue.borrow_mut().take();
                        let promise = match maybe_queue {
                            Some(queue) => {
                                queue.then_else(move |_| GNS::lookup_loop(&mut sr, id, map))
                            }
                            None => GNS::lookup_loop(&mut sr, id, map),
                        };

                        let (p, f) = Promise::and_fulfiller();
                        *read_queue.borrow_mut() = Some(p);

                        promise.map_else(|r| {
                            f.resolve(Ok(()));
                            r
                        })
                    }
                }
            })
            .lift()
    }

    fn lookup_loop(
        sr: &mut ServiceReader,
        id: u32,
        map: Rc<RefCell<HashMap<u32, Vec<Record>>>>,
    ) -> Promise<Vec<Record>, LookupError> {
        let mut sr2 = sr.clone();
        let map2 = map.clone();
        sr.read_message().lift().then(move |(tpe, mr)| {
            match GNS::parse_lookup_result(tpe, mr, map) {
                Ok(()) => {
                    // read again if the id is not available yet
                    let result = map2.borrow_mut().remove(&id);
                    match result {
                        Some(x) => return Promise::ok(x),
                        None => return GNS::lookup_loop(&mut sr2, id, map2),
                    };
                }
                Err(e) => return Promise::err(e),
            }
        })
    }

    // in this function, results are inserted in to the map
    fn parse_lookup_result(
        tpe: MessageType,
        mut reader: Cursor<Vec<u8>>,
        map: Rc<RefCell<HashMap<u32, Vec<Record>>>>,
    ) -> Result<(), LookupError> {
        match tpe {
            MessageType::GNS_LOOKUP_RESULT => {
                let mut records = Vec::new();

                let id = reader.read_u32::<BigEndian>()?;
                let rd_count = reader.read_u32::<BigEndian>()?;
                for _ in 0..rd_count {
                    let rec = Record::deserialize(&mut reader)?;
                    records.push(rec);
                }

                if !records.is_empty() {
                    map.borrow_mut().insert(id, records);
                }
            }
            x => return Err(LookupError::InvalidType { tpe: x }), // TODO reconnect here instead of returning error
        };
        Ok(())
    }
}

/// Packed struct representing GNUNET_GNS_ClientLookupMessage.
#[repr(C, packed)]
struct LookupMessage {
    header: MessageHeader,
    id: u32,
    zone: EcdsaPublicKey,
    options: i16,     // LocalOptions
    have_key: i16,    // 0 or 1
    record_type: i32, // RecordType
    shorten_key: EcdsaPrivateKey,
    // followed by 0-terminated name to look up
}

impl LookupMessage {
    fn new(
        id: u32,
        zone: EcdsaPublicKey,
        options: LocalOptions,
        shorten: Option<EcdsaPrivateKey>,
        record_type: RecordType,
        name: &str,
    ) -> Result<LookupMessage, LookupError> {
        let name_len = name.len();
        if name_len > ll::GNUNET_DNSPARSER_MAX_NAME_LENGTH as usize {
            return Err(LookupError::NameTooLong {
                name: name.to_string(),
            });
        };

        let msg_len = match (::std::mem::size_of::<LookupMessage>() + name_len + 1).to_u16() {
            Some(x) => x,
            _ => {
                return Err(LookupError::NameTooLong {
                    name: name.to_string(),
                })
            }
        };

        Ok(LookupMessage {
            header: MessageHeader {
                len: msg_len.to_be(),
                tpe: (MessageType::GNS_LOOKUP as u16).to_be(),
            },
            id: id.to_be(),
            zone: zone,
            options: (options as i16).to_be(),
            have_key: (shorten.is_some() as i16).to_be(),
            record_type: (record_type as i32).to_be(),
            shorten_key: match shorten {
                Some(x) => x,
                None => EcdsaPrivateKey::zeros(),
            },
        })
    }
}

impl MessageTrait for LookupMessage {
    // Note that this does not include the 0-terminated string.
    fn into_slice(&self) -> &[u8] {
        message_to_slice!(LookupMessage, self)
    }
}

/// Errors returned by `gns::lookup`.
#[derive(Debug, Error)]
pub enum ConnectLookupError {
    #[error("Failed to connect to the GNS service. Reason: {source}")]
    Connect {
        #[from]
        source: service::ConnectError,
    },
    #[error("Failed to perform the lookup.. Reason: {source}")]
    Lookup {
        #[from]
        source: LookupError,
    },
    #[error("There was an I/O error communicating with the service. Specifically {source}")]
    Io {
        #[from]
        source: io::Error,
    },
}

/// Lookup a GNS record in the given zone.
///
/// If `shorten` is not `None` then the result is added to the given shorten zone.
/// The returned promise can only be fulfilled when a record is found.
/// The user should consider setting a timeout in case no record can be found.
///
/// # Example
///
/// ```rust
/// use gnunet::{Cfg, identity, gns};
/// use gnunet::util::asynch;
///
/// let config = Cfg::default().unwrap();
/// let mut event_port = asynch::EventPort::new().unwrap();
/// let network = event_port.get_network();
/// let gns_master = ::std::rc::Rc::new("gns-master".to_string());
/// let gnu_org = ::std::rc::Rc::new("gnu.org".to_string());
///
/// asynch::EventLoop::top_level(|wait_scope| -> Result<(), ::std::io::Error> {
///     let ego = identity::get_default_ego(&config, gns_master, &network).wait(wait_scope, &mut event_port).unwrap();
///     let pk = ego.get_public_key();
///     let record = gns::lookup(&config,
///                              &network,
///                              gnu_org,
///                              pk,
///                              gns::RecordType::A,
///                              gns::LocalOptions::LocalMaster,
///                              None).wait(wait_scope, &mut event_port).unwrap();
///     println!("Got the IPv4 record for gnu.org: {}", record);
///     Ok(())
/// }).expect("top_level");
/// ```
///
/// # Note
///
/// This is a convenience function that connects to the GNS service, performs the lookup, retrieves
/// one result, then disconects. If you are performing multiple lookups this function should be
/// avoided and `GNS::lookup_in_zone` used instead.
pub fn lookup(
    cfg: &Cfg,
    network: &Network,
    name: Rc<String>,
    zone: EcdsaPublicKey,
    record_type: RecordType,
    options: LocalOptions,
    shorten: Option<EcdsaPrivateKey>,
) -> Promise<Record, ConnectLookupError> {
    GNS::connect(cfg, network).lift().then(move |mut gns| {
        println!("connected to GNS");
        gns.lookup(name, zone, record_type, options, shorten)
            .lift()
            .map(move |mut result| {
                // it's ok to unwrap here because gns.lookup does not stop if it hasn't found a result
                Ok(result.pop().unwrap())
            })
    })
}

/// Errors returned by `gns::lookup_in_master`.
#[derive(Debug, Error)]
pub enum ConnectLookupInMasterError {
    #[error("Failed to connect to the GNS service and perform the lookup. Reason: {source}")]
    GnsLookup {
        #[from]
        source: ConnectLookupError,
    },
    #[error("Failed to retrieve the default identity for gns-master from the identity service. Reason: {source}")]
    IdentityGetDefaultEgo {
        #[from]
        source: identity::ConnectGetDefaultEgoError,
    },
    #[error("There was an I/O error communicating with the service. Specifically {source}")]
    Io {
        #[from]
        source: io::Error,
    },
}

/// Lookup a GNS record in the master zone.
///
/// If `shorten` is not `None` then the result is added to the given shorten zone.
/// The returned promise can only be fulfilled when a record is found.
/// The user should consider setting a timeout in case no record can be found.
///
/// # Example
///
/// ```rust
/// use gnunet::{Cfg, gns};
/// use gnunet::util::asynch;
///
/// let config = Cfg::default().unwrap();
/// let mut event_port = asynch::EventPort::new().unwrap();
/// let network = event_port.get_network();
/// let gnu_org = ::std::rc::Rc::new("gnu.org".to_string());
///
/// asynch::EventLoop::top_level(|wait_scope| -> Result<(), ::std::io::Error> {
///     let record_promise = gnunet::lookup_in_master(&config, &network, gnu_org, gns::RecordType::A, None);
///     let record = record_promise.wait(wait_scope, &mut event_port).unwrap();
///     println!("Got the IPv4 record for gnu.org: {}", record);
///     Ok(())
/// }).expect("top_level");
/// ```
///
/// # Note
///
/// This is a convenience function that connects to the identity service, fetches the default ego
/// for gns-master, then connects to the GNS service, performs the lookup, retrieves one result,
/// then disconnects from everything. If you are performing lots of lookups this function should be
/// avoided and `GNS::lookup` should be used instead.
pub fn lookup_in_master(
    cfg: &Cfg,
    network: &Network,
    name: Rc<String>,
    record_type: RecordType,
    shorten: Option<EcdsaPrivateKey>,
) -> Promise<Record, ConnectLookupInMasterError> {
    println!("Getting default ego");
    let network2 = network.clone();
    let cfg2 = cfg.clone();
    identity::get_default_ego(cfg, Rc::new("gns-master".to_string()), network)
        .lift()
        .then(move |ego| {
            let pk = ego.get_public_key();
            let opt = {
                let mut it = name.split('.');
                match (it.next(), it.next(), it.next()) {
                    (Some(_), Some("gnu"), None) => LocalOptions::NoDHT,
                    _ => LocalOptions::LocalMaster,
                }
            };
            println!("doing lookup");
            lookup(&cfg2, &network2, name, pk, record_type, opt, shorten).lift()
        })
}
