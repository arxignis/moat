use std::net::SocketAddr;
use std::time::Duration;
use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::time::timeout;
use proxy_protocol::{ProxyHeader, parse};
use bytes::Bytes;

/// Information extracted from PROXY protocol header
#[derive(Debug, Clone)]
pub struct ProxyInfo {
    pub source_addr: SocketAddr,
    pub dest_addr: SocketAddr,
    pub version: ProxyVersion,
}

#[derive(Debug, Clone)]
pub enum ProxyVersion {
    V1,
    V2,
}

/// Parse PROXY protocol header from a TCP stream
pub async fn parse_proxy_protocol<R>(
    stream: &mut R,
    timeout_ms: u64,
) -> Result<Option<ProxyInfo>>
where
    R: AsyncRead + Unpin,
{
    let timeout_duration = Duration::from_millis(timeout_ms);

    let result = timeout(timeout_duration, async {
        // Read enough bytes to detect PROXY protocol (at least 107 bytes for v1, 16 for v2)
        let mut buffer = vec![0u8; 107];
        let bytes_read = stream.read(&mut buffer).await?;

        if bytes_read == 0 {
            return Ok(None);
        }

        // Truncate buffer to actual bytes read
        buffer.truncate(bytes_read);

        // Convert to Bytes for the proxy-protocol crate
        let mut bytes = Bytes::from(buffer);

        // Try to decode PROXY protocol header
        match parse(&mut bytes) {
            Ok(header) => {
                match header {
                    ProxyHeader::Version1 { addresses } => {
                        match addresses {
                            proxy_protocol::version1::ProxyAddresses::Ipv4 { source, destination } => {
                                Ok(Some(ProxyInfo {
                                    source_addr: SocketAddr::V4(source),
                                    dest_addr: SocketAddr::V4(destination),
                                    version: ProxyVersion::V1,
                                }))
                            }
                            proxy_protocol::version1::ProxyAddresses::Ipv6 { source, destination } => {
                                Ok(Some(ProxyInfo {
                                    source_addr: SocketAddr::V6(source),
                                    dest_addr: SocketAddr::V6(destination),
                                    version: ProxyVersion::V1,
                                }))
                            }
                            proxy_protocol::version1::ProxyAddresses::Unknown => {
                                // Unknown addresses - return None
                                Ok(None)
                            }
                        }
                    }
                    ProxyHeader::Version2 { addresses, .. } => {
                        match addresses {
                            proxy_protocol::version2::ProxyAddresses::Ipv4 { source, destination } => {
                                Ok(Some(ProxyInfo {
                                    source_addr: SocketAddr::V4(source),
                                    dest_addr: SocketAddr::V4(destination),
                                    version: ProxyVersion::V2,
                                }))
                            }
                            proxy_protocol::version2::ProxyAddresses::Ipv6 { source, destination } => {
                                Ok(Some(ProxyInfo {
                                    source_addr: SocketAddr::V6(source),
                                    dest_addr: SocketAddr::V6(destination),
                                    version: ProxyVersion::V2,
                                }))
                            }
                            proxy_protocol::version2::ProxyAddresses::Unspec => {
                                // Unspec addresses - return None
                                Ok(None)
                            }
                            proxy_protocol::version2::ProxyAddresses::Unix { .. } => {
                                // Unix socket addresses - return None
                                Ok(None)
                            }
                        }
                    }
                    _ => {
                        // Handle any future versions or unknown variants
                        Ok(None)
                    }
                }
            }
            Err(_e) => {
                // No PROXY protocol header found
                Ok(None)
            }
        }
    }).await;

    match result {
        Ok(Ok(proxy_info)) => Ok(proxy_info),
        Ok(Err(e)) => Err(e),
        Err(_) => {
            // Timeout occurred
            Err(anyhow::anyhow!("PROXY protocol parsing timeout"))
        }
    }
}

/// A wrapper around a TCP stream that handles PROXY protocol parsing
///
/// This wrapper transparently handles PROXY protocol v1 and v2 parsing and provides
/// access to the real client address information while preserving the original
/// stream for further use.
pub struct ProxyProtocolStream<T> {
    inner: T,
    proxy_info: Option<ProxyInfo>,
}

impl<T> ProxyProtocolStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn new(
        stream: T,
        proxy_protocol_enabled: bool,
        timeout_ms: u64,
    ) -> Result<Self> {
        if proxy_protocol_enabled {
            let mut temp_stream = stream;
            let proxy_info = parse_proxy_protocol(&mut temp_stream, timeout_ms).await?;
            Ok(Self {
                inner: temp_stream,
                proxy_info,
            })
        } else {
            Ok(Self {
                inner: stream,
                proxy_info: None,
            })
        }
    }

    pub fn proxy_info(&self) -> Option<&ProxyInfo> {
        self.proxy_info.as_ref()
    }

    pub fn real_client_addr(&self) -> Option<SocketAddr> {
        self.proxy_info.as_ref().map(|info| info.source_addr)
    }

    /// Returns true if PROXY protocol was detected and parsed successfully
    pub fn has_proxy_info(&self) -> bool {
        self.proxy_info.is_some()
    }

    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    pub fn inner(self) -> T {
        self.inner
    }
}

impl<T> AsyncRead for ProxyProtocolStream<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for ProxyProtocolStream<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use proxy_protocol::encode;

    #[tokio::test]
    async fn test_parse_proxy_v1_ipv4() {
        // Create PROXY protocol v1 IPv4 header
        let header = "PROXY TCP4 192.168.1.100 192.168.1.200 12345 80\r\n";
        let mut stream = Cursor::new(header.as_bytes());

        let result = parse_proxy_protocol(&mut stream, 1000).await.unwrap();

        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.source_addr.ip(), "192.168.1.100".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(info.source_addr.port(), 12345);
        assert_eq!(info.dest_addr.ip(), "192.168.1.200".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(info.dest_addr.port(), 80);
        matches!(info.version, ProxyVersion::V1);
    }

    #[tokio::test]
    async fn test_parse_proxy_v1_ipv6() {
        // Create PROXY protocol v1 IPv6 header
        let header = "PROXY TCP6 2001:db8::1 2001:db8::2 12345 80\r\n";
        let mut stream = Cursor::new(header.as_bytes());

        let result = parse_proxy_protocol(&mut stream, 1000).await.unwrap();

        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.source_addr.ip(), "2001:db8::1".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(info.source_addr.port(), 12345);
        assert_eq!(info.dest_addr.ip(), "2001:db8::2".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(info.dest_addr.port(), 80);
        matches!(info.version, ProxyVersion::V1);
    }

    #[tokio::test]
    async fn test_parse_proxy_v2_ipv4() {
        // Create PROXY protocol v2 IPv4 header using the crate's builder
        let header = ProxyHeader::Version2 {
            command: proxy_protocol::version2::ProxyCommand::Proxy,
            transport_protocol: proxy_protocol::version2::ProxyTransportProtocol::Stream,
            addresses: proxy_protocol::version2::ProxyAddresses::Ipv4 {
                source: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(192, 168, 1, 100), 12345),
                destination: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(192, 168, 1, 200), 80),
            },
            extensions: vec![],
        };

        let mut data = encode(header).unwrap();
        let mut stream = Cursor::new(data.as_mut());

        let result = parse_proxy_protocol(&mut stream, 1000).await.unwrap();

        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.source_addr.ip(), "192.168.1.100".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(info.source_addr.port(), 12345);
        assert_eq!(info.dest_addr.ip(), "192.168.1.200".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(info.dest_addr.port(), 80);
        matches!(info.version, ProxyVersion::V2);
    }

    #[tokio::test]
    async fn test_parse_proxy_v2_ipv6() {
        // Create PROXY protocol v2 IPv6 header using the crate's builder
        let header = ProxyHeader::Version2 {
            command: proxy_protocol::version2::ProxyCommand::Proxy,
            transport_protocol: proxy_protocol::version2::ProxyTransportProtocol::Stream,
            addresses: proxy_protocol::version2::ProxyAddresses::Ipv6 {
                source: std::net::SocketAddrV6::new(
                    std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
                    12345, 0, 0
                ),
                destination: std::net::SocketAddrV6::new(
                    std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2),
                    80, 0, 0
                ),
            },
            extensions: vec![],
        };

        let mut data = encode(header).unwrap();
        let mut stream = Cursor::new(data.as_mut());

        let result = parse_proxy_protocol(&mut stream, 1000).await.unwrap();

        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.source_addr.ip(), "2001:db8::1".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(info.source_addr.port(), 12345);
        assert_eq!(info.dest_addr.ip(), "2001:db8::2".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(info.dest_addr.port(), 80);
        matches!(info.version, ProxyVersion::V2);
    }

    #[tokio::test]
    async fn test_no_proxy_header() {
        // Test with data that doesn't contain a PROXY protocol header
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut stream = Cursor::new(data);

        let result = parse_proxy_protocol(&mut stream, 1000).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_proxy_protocol_stream_wrapper() {
        // Test the wrapper functionality
        let header = "PROXY TCP4 192.168.1.100 192.168.1.200 12345 80\r\n";
        let data = format!("{}{}", header, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        let stream = Cursor::new(data.into_bytes());

        let wrapper = ProxyProtocolStream::new(stream, true, 1000).await.unwrap();

        assert!(wrapper.has_proxy_info());
        assert_eq!(wrapper.real_client_addr().unwrap().ip(), "192.168.1.100".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(wrapper.real_client_addr().unwrap().port(), 12345);
    }
}
