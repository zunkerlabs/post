//! Tor transport: one request per connection, each on its own circuit.
//!
//! Spec: `spec/zip-draft-1435.md` § Routing (L332–350) and Appendix A, Tor
//! (L490–501). A session is "a connection over a circuit shared with no other
//! session" (L496). Every request here opens a new connection with a new
//! isolation token, so every Deposit, and every Fetch, gets its own session:
//! no session ever carries two Mailbox IDs (L348–349).
//!
//! There is no direct-connection path. If neither arti nor a local tor is
//! available, requests fail (L349–350: a wallet "MUST NOT bypass the anonymity
//! network when it is unavailable").

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use arti_client::config::{BoolOrAuto, TorClientConfigBuilder};
use arti_client::{IsolationToken, StreamPrefs, TorClient};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tor_rtcompat::PreferredRuntime;
use zunker_server::wire::{read_frame, write_frame};

/// Default SOCKS port of a system tor. Spec: Appendix A, Tor (L496).
pub const DEFAULT_SOCKS_PROXY: &str = "127.0.0.1:9050";

/// Largest Fetch response accepted. Servers choose their own budget (§ Mailbox
/// Servers, L315–316); 16 MiB is four times the reference server's default.
pub const MAX_RESPONSE_LEN: usize = 16 * 1024 * 1024;

/// Time allowed for one request, from opening the circuit to the last byte.
/// Spec: none (operational limit).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Time allowed for arti to bootstrap before falling back to a local tor.
/// Spec: none (operational limit).
pub const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(180);

/// A version 3 onion service address and port, e.g. `<56 chars>.onion:7878`.
///
/// Spec: Appendix A, Tor (L494–495): the 32-byte key of a v3 onion service;
/// the port is TBD in the draft, so it is part of the address here.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OnionAddr {
    host: String,
    port: u16,
}

impl OnionAddr {
    /// The `.onion` host name. Spec: Appendix A, Tor (L494).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port. Spec: Appendix A, Tor (L494–495, port TBD).
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for OnionAddr {
    /// `host:port`. Spec: Appendix A, Tor (L494–495).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// Why an onion address was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadOnionAddr;

impl fmt::Display for BadOnionAddr {
    /// Spec: none (diagnostics only).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected <56 base32 characters>.onion:<port>")
    }
}

impl std::error::Error for BadOnionAddr {}

impl FromStr for OnionAddr {
    type Err = BadOnionAddr;

    /// Parses `<56 base32 chars>.onion:<port>`. A v3 address encodes
    /// `pubkey || checksum || version 3`, so the last character is `d`; the
    /// checksum is left to Tor. Spec: Appendix A, Tor (L494–495).
    fn from_str(s: &str) -> Result<Self, BadOnionAddr> {
        let (host, port) = s.rsplit_once(':').ok_or(BadOnionAddr)?;
        let port: u16 = port.parse().map_err(|_| BadOnionAddr)?;
        let label = host.strip_suffix(".onion").ok_or(BadOnionAddr)?;
        let base32 = |c: char| c.is_ascii_lowercase() || ('2'..='7').contains(&c);
        if port == 0 || label.len() != 56 || !label.chars().all(base32) || !label.ends_with('d') {
            return Err(BadOnionAddr);
        }
        Ok(OnionAddr {
            host: host.to_owned(),
            port,
        })
    }
}

/// Why a request failed. None of these leads to a retry outside Tor.
#[derive(Debug)]
pub enum TransportError {
    /// Neither arti nor a local tor could be used.
    TorUnavailable(String),
    /// The circuit or the connection to the onion service failed.
    Connect(String),
    /// Reading or writing the request or response failed.
    Io(std::io::Error),
    /// The request took longer than [`REQUEST_TIMEOUT`].
    Timeout,
    /// The response was larger than [`MAX_RESPONSE_LEN`].
    ResponseTooLarge,
    /// The address is not reachable by this transport.
    UnknownAddress,
}

impl fmt::Display for TransportError {
    /// Spec: none (diagnostics only).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::TorUnavailable(why) => write!(
                f,
                "Tor is unavailable ({why}); refusing to connect outside Tor"
            ),
            TransportError::Connect(why) => write!(f, "cannot reach the onion service: {why}"),
            TransportError::Io(e) => write!(f, "connection failed: {e}"),
            TransportError::Timeout => f.write_str("request timed out"),
            TransportError::ResponseTooLarge => f.write_str("response too large"),
            TransportError::UnknownAddress => {
                f.write_str("address not reachable by this transport")
            }
        }
    }
}

impl std::error::Error for TransportError {}

impl From<std::io::Error> for TransportError {
    /// Spec: none (error conversion).
    fn from(e: std::io::Error) -> Self {
        TransportError::Io(e)
    }
}

/// Where arti keeps its state and directory cache.
///
/// Spec: none (configuration).
#[derive(Clone, Debug)]
pub struct ArtiDirs {
    /// Guard and other persistent state.
    pub state: PathBuf,
    /// Downloaded directory documents.
    pub cache: PathBuf,
}

/// How a client reaches Mailbox Servers. Every variant goes through Tor except
/// [`Transport::insecure_loopback`], which only reaches loopback addresses and
/// exists for in-process tests.
///
/// Spec: § Routing (L332–350), Appendix A, Tor (L490–501).
#[derive(Clone)]
pub struct Transport(Inner);

#[derive(Clone)]
enum Inner {
    Arti(Arc<TorClient<PreferredRuntime>>),
    Socks5(SocketAddr),
    Loopback(Arc<HashMap<OnionAddr, SocketAddr>>),
}

impl fmt::Debug for Transport {
    /// Spec: none (diagnostics only).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            Inner::Arti(_) => "Transport::Arti",
            Inner::Socks5(_) => "Transport::Socks5",
            Inner::Loopback(_) => "Transport::InsecureLoopback",
        })
    }
}

impl Transport {
    /// Tor, preferring an embedded arti client and falling back to a local
    /// tor's SOCKS port. Fails, rather than connecting directly, if neither
    /// works. Spec: § Routing (L349–350).
    pub async fn tor(dirs: &ArtiDirs, socks_proxy: SocketAddr) -> Result<Self, TransportError> {
        let arti_err = match tokio::time::timeout(BOOTSTRAP_TIMEOUT, Self::arti(dirs)).await {
            Ok(Ok(t)) => return Ok(t),
            Ok(Err(e)) => e.to_string(),
            Err(_) => "bootstrap timed out".to_owned(),
        };
        Self::socks5(socks_proxy).await.map_err(|socks_err| {
            TransportError::TorUnavailable(format!(
                "arti: {arti_err}; tor at {socks_proxy}: {socks_err}"
            ))
        })
    }

    /// An embedded arti client, bootstrapped. Spec: Appendix A, Tor (L496).
    pub async fn arti(dirs: &ArtiDirs) -> Result<Self, TransportError> {
        let config = TorClientConfigBuilder::from_directories(&dirs.state, &dirs.cache)
            .build()
            .map_err(|e| TransportError::TorUnavailable(e.to_string()))?;
        let client = TorClient::create_bootstrapped(config)
            .await
            .map_err(|e| TransportError::TorUnavailable(e.to_string()))?;
        Ok(Transport(Inner::Arti(client)))
    }

    /// A local tor's SOCKS5 port. Checks that something is listening there;
    /// each request then authenticates with fresh random credentials, which
    /// tor's default `IsolateSOCKSAuth` puts on a new circuit.
    /// Spec: Appendix A, Tor (L496).
    pub async fn socks5(proxy: SocketAddr) -> Result<Self, TransportError> {
        if !proxy.ip().is_loopback() {
            return Err(TransportError::TorUnavailable(
                "the SOCKS proxy must be on this machine".to_owned(),
            ));
        }
        TcpStream::connect(proxy)
            .await
            .map_err(|e| TransportError::TorUnavailable(e.to_string()))?;
        Ok(Transport(Inner::Socks5(proxy)))
    }

    /// **For tests only.** Maps onion addresses to loopback TCP addresses, so
    /// in-process servers can be reached without Tor. Rejects any address that
    /// is not loopback, so it can never carry traffic off the machine.
    /// Spec: none (test harness).
    pub fn insecure_loopback(map: HashMap<OnionAddr, SocketAddr>) -> Result<Self, TransportError> {
        if map.values().any(|a| !a.ip().is_loopback()) {
            return Err(TransportError::UnknownAddress);
        }
        Ok(Transport(Inner::Loopback(Arc::new(map))))
    }

    /// Whether this transport goes through Tor. Spec: § Routing (L349–350).
    pub fn is_tor(&self) -> bool {
        !matches!(self.0, Inner::Loopback(_))
    }

    /// Sends one framed request on a new session and, if `expect_response`,
    /// reads one framed response. Deposits expect none (§ Mailbox Servers,
    /// L311); a Fetch the server drops yields `Ok(None)` (L326–328).
    ///
    /// Spec: § Routing (L348–349), Appendix A, Tor (L496–498).
    pub async fn request(
        &self,
        to: &OnionAddr,
        request: &[u8],
        expect_response: bool,
    ) -> Result<Option<Vec<u8>>, TransportError> {
        let work = async {
            match &self.0 {
                Inner::Arti(client) => {
                    let mut prefs = StreamPrefs::new();
                    prefs
                        .connect_to_onion_services(BoolOrAuto::Explicit(true))
                        .set_isolation(IsolationToken::new());
                    let stream = client
                        .connect_with_prefs((to.host(), to.port()), &prefs)
                        .await
                        .map_err(|e| TransportError::Connect(e.to_string()))?;
                    exchange(stream, request, expect_response).await
                }
                Inner::Socks5(proxy) => {
                    let (user, pass) = fresh_socks_credentials()?;
                    let stream = tokio_socks::tcp::Socks5Stream::connect_with_password(
                        *proxy,
                        (to.host(), to.port()),
                        &user,
                        &pass,
                    )
                    .await
                    .map_err(|e| TransportError::Connect(e.to_string()))?;
                    exchange(stream, request, expect_response).await
                }
                Inner::Loopback(map) => {
                    let addr = map.get(to).ok_or(TransportError::UnknownAddress)?;
                    exchange(TcpStream::connect(addr).await?, request, expect_response).await
                }
            }
        };
        tokio::time::timeout(REQUEST_TIMEOUT, work)
            .await
            .map_err(|_| TransportError::Timeout)?
    }
}

/// Random SOCKS username and password, unique to one request, so that tor
/// isolates its stream onto a circuit of its own (`IsolateSOCKSAuth`).
/// Spec: Appendix A, Tor (L496).
fn fresh_socks_credentials() -> Result<(String, String), TransportError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|e| TransportError::TorUnavailable(format!("no OS randomness: {e}")))?;
    Ok((hex::encode(&bytes[..16]), hex::encode(&bytes[16..])))
}

/// Writes the request frame, half-closes, and reads the response frame if one
/// is expected, or else waits for the server to close. A connection closed
/// without a response means the server dropped the request (or, for a
/// Deposit, handled it). Spec: Appendix A, Tor (L497–498); § Mailbox Servers (L326–328).
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    request: &[u8],
    expect_response: bool,
) -> Result<Option<Vec<u8>>, TransportError> {
    write_frame(&mut stream, request).await?;
    stream.shutdown().await?;
    if !expect_response {
        // The server closes a Deposit's connection, without a response, once
        // it has handled it. Waiting for that close means a returned Deposit
        // has reached the server; stored and dropped look the same.
        let mut sink = [0u8; 64];
        loop {
            match stream.read(&mut sink).await {
                Ok(0) => return Ok(None),
                Ok(_) => continue,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(e.into()),
            }
        }
    }
    match read_frame(&mut stream, MAX_RESPONSE_LEN).await {
        Ok(Some(frame)) => Ok(Some(frame)),
        Ok(None) => Err(TransportError::ResponseTooLarge),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    const ONION: &str = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:7878";

    /// v3 onion addresses parse; anything else, including IP addresses and
    /// host names that would bypass Tor, is rejected. Spec: Appendix A, Tor (L494–495).
    #[test]
    fn onion_addresses() {
        let a: OnionAddr = ONION.parse().unwrap();
        assert_eq!(a.port(), 7878);
        assert_eq!(a.to_string(), ONION);
        for bad in [
            "127.0.0.1:7878",
            "example.com:7878",
            "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion",
            "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:0",
            "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscrya.onion:7878",
            "PG6MMJIYJMCRSSLVYKFWNNTLARU7P5SVN6Y2YMMJU6NUBXNDF4PSCRYD.onion:7878",
            "facebookcorewwwi.onion:443",
        ] {
            assert!(bad.parse::<OnionAddr>().is_err(), "{bad}");
        }
    }

    /// With no local tor, the SOCKS transport refuses to start, and a
    /// non-loopback proxy is refused outright: there is no direct fallback.
    /// Spec: § Routing (L349–350).
    #[tokio::test]
    async fn no_tor_means_no_transport() {
        let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = unused.local_addr().unwrap();
        drop(unused);
        assert!(matches!(
            Transport::socks5(addr).await,
            Err(TransportError::TorUnavailable(_))
        ));
        assert!(matches!(
            Transport::socks5("192.0.2.1:9050".parse().unwrap()).await,
            Err(TransportError::TorUnavailable(_))
        ));
    }

    /// The test transport only maps to loopback, and only for listed onions.
    /// Spec: none (test harness).
    #[tokio::test]
    async fn loopback_is_loopback_only() {
        let onion: OnionAddr = ONION.parse().unwrap();
        let remote = HashMap::from([(onion.clone(), "192.0.2.1:7878".parse().unwrap())]);
        assert!(Transport::insecure_loopback(remote).is_err());
        let t = Transport::insecure_loopback(HashMap::new()).unwrap();
        assert!(!t.is_tor());
        assert!(matches!(
            t.request(&onion, b"x", false).await,
            Err(TransportError::UnknownAddress)
        ));
    }

    /// Each SOCKS request authenticates with fresh credentials.
    /// Spec: Appendix A, Tor (L496): no two sessions share a circuit.
    #[test]
    fn socks_credentials_are_fresh() {
        let a = fresh_socks_credentials().unwrap();
        let b = fresh_socks_credentials().unwrap();
        assert_ne!(a, b);
        assert_ne!(a.0, a.1);
        assert_eq!(a.0.len(), 32);
    }

    /// A SOCKS5 server that records the credentials of each connection and
    /// then forwards nothing. Each request uses a different username, so tor
    /// would isolate them. Spec: Appendix A, Tor (L496).
    #[tokio::test]
    async fn socks_requests_use_distinct_credentials() {
        use tokio::io::AsyncReadExt;
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = proxy.local_addr().unwrap();
        let seen = tokio::spawn(async move {
            let mut users = Vec::new();
            for _ in 0..3 {
                let (mut s, _) = proxy.accept().await.unwrap();
                if users.is_empty() {
                    // The probe in `Transport::socks5` connects and closes.
                    let (s2, _) = proxy.accept().await.unwrap();
                    s = s2;
                }
                let mut greet = [0u8; 2];
                s.read_exact(&mut greet).await.unwrap();
                let mut methods = vec![0u8; greet[1] as usize];
                s.read_exact(&mut methods).await.unwrap();
                assert!(methods.contains(&2), "username/password offered");
                s.write_all(&[5, 2]).await.unwrap();
                let mut ver_ulen = [0u8; 2];
                s.read_exact(&mut ver_ulen).await.unwrap();
                let mut user = vec![0u8; ver_ulen[1] as usize];
                s.read_exact(&mut user).await.unwrap();
                users.push(user);
                // Refuse authentication; the client gives up on this request.
                s.write_all(&[1, 1]).await.unwrap();
            }
            users
        });
        let t = Transport::socks5(addr).await.unwrap();
        let onion: OnionAddr = ONION.parse().unwrap();
        for _ in 0..3 {
            assert!(t.request(&onion, b"req", false).await.is_err());
        }
        let users = seen.await.unwrap();
        assert_eq!(users.len(), 3);
        assert!(users[0] != users[1] && users[1] != users[2] && users[0] != users[2]);
    }
}
