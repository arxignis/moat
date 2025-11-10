use std::net::SocketAddr;
use std::time::Duration;
use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, BufReader};
use tokio::time::timeout;
use proxy_protocol::{ProxyHeader, parse};
use bytes::{Bytes, Buf};

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

/// Parse PROXY protocol header from a buffered stream
/// Returns the proxy info and a buffered reader with unconsumed data preserved
pub async fn parse_proxy_protocol_buffered<R>(
    stream: R,
    timeout_ms: u64,
) -> Result<(Option<ProxyInfo>, BufReader<ChainedReader<R>>)>
where
    R: AsyncRead + Unpin,
{
    log::trace!("Starting PROXY protocol parse with {}ms timeout", timeout_ms);
    let mut reader = BufReader::with_capacity(512, stream);
    let timeout_duration = Duration::from_millis(timeout_ms);

    let proxy_info = timeout(timeout_duration, async {
        // Read enough bytes to detect PROXY protocol
        // v1: up to 108 bytes (including \r\n)
        // v2: 16 bytes header + variable length
        let mut peek_buffer = vec![0u8; 232]; // Enough for v2 with reasonable extensions

        let mut total_read = 0;
        while total_read < peek_buffer.len() {
            let n = reader.read(&mut peek_buffer[total_read..]).await?;
            if n == 0 {
                log::trace!("PROXY protocol parse: EOF reached after reading {} bytes", total_read);
                break; // EOF
            }
            total_read += n;
            log::trace!("PROXY protocol parse: read {} bytes (total: {})", n, total_read);

            // Try parsing with what we have so far
            let mut bytes = Bytes::copy_from_slice(&peek_buffer[..total_read]);
            let bytes_before = bytes.remaining();

            match parse(&mut bytes) {
                Ok(header) => {
                    let consumed = bytes_before - bytes.remaining();
                    log::trace!("PROXY protocol header successfully parsed: consumed {} bytes, total read: {}", consumed, total_read);

                    // We successfully parsed a header
                    // The consumed bytes are the header, remaining bytes are application data
                    let info = header_to_proxy_info(header);

                    // Return remaining bytes to the buffer
                    // We need to create a new reader that has the unconsumed data
                    if total_read > consumed {
                        // We read more than the header, need to preserve the extra bytes
                        let remaining = &peek_buffer[consumed..total_read];
                        log::trace!("PROXY protocol: preserving {} extra bytes after header", remaining.len());
                        let new_reader = create_reader_with_prefix(reader, remaining.to_vec());
                        return Ok((info, new_reader));
                    }

                    // No extra bytes, but wrap in empty ChainedReader for type consistency
                    log::trace!("PROXY protocol: no extra bytes to preserve");
                    let new_reader = create_reader_with_prefix(reader, Vec::new());
                    return Ok((info, new_reader));
                }
                Err(e) => {
                    log::trace!("PROXY protocol parse attempt failed: {}", e);

                    // Check if this looks like a PROXY protocol header at all
                    if total_read >= 8 {
                        let prefix = &peek_buffer[..8];
                        // v1 starts with "PROXY "
                        // v2 starts with specific signature
                        let is_v1_start = prefix.starts_with(b"PROXY ");
                        let is_v2_start = prefix.starts_with(&[0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51]);

                        if !is_v1_start && !is_v2_start {
                            // Definitely not PROXY protocol, return all data to buffer
                            log::trace!("No PROXY protocol detected (first 8 bytes don't match signature), treating as plain connection. Preview: {:?}",
                                String::from_utf8_lossy(&prefix[..prefix.len().min(8)]));
                            let new_reader = create_reader_with_prefix(reader, peek_buffer[..total_read].to_vec());
                            return Ok((None, new_reader));
                        }

                        log::trace!("PROXY protocol signature detected but incomplete, continuing to read...");
                    }

                    // Might be PROXY protocol but incomplete, keep reading
                    continue;
                }
            }
        }

        // Reached EOF or buffer limit without parsing successfully
        // Return all data to the buffer
        if total_read > 0 {
            log::trace!("PROXY protocol parse completed without header (read {} bytes), preserving all data", total_read);
            let new_reader = create_reader_with_prefix(reader, peek_buffer[..total_read].to_vec());
            Ok((None, new_reader))
        } else {
            log::trace!("PROXY protocol parse: no data read");
            let new_reader = create_reader_with_prefix(reader, Vec::new());
            Ok((None, new_reader))
        }
    }).await;

    match proxy_info {
        Ok(Ok((info, reader))) => {
            if info.is_some() {
                log::trace!("PROXY protocol parsing successful");
            } else {
                log::trace!("PROXY protocol parsing completed: no header found, treating as plain connection");
            }
            Ok((info, reader))
        },
        Ok(Err(e)) => {
            log::warn!("PROXY protocol parsing error: {}", e);
            Err(e)
        },
        Err(_) => {
            log::warn!("PROXY protocol parsing timeout after {}ms", timeout_ms);
            Err(anyhow::anyhow!("PROXY protocol parsing timeout"))
        },
    }
}

/// Convert ProxyHeader to ProxyInfo
fn header_to_proxy_info(header: ProxyHeader) -> Option<ProxyInfo> {
    match header {
        ProxyHeader::Version1 { addresses } => {
            match addresses {
                proxy_protocol::version1::ProxyAddresses::Ipv4 { source, destination } => {
                    Some(ProxyInfo {
                        source_addr: SocketAddr::V4(source),
                        dest_addr: SocketAddr::V4(destination),
                        version: ProxyVersion::V1,
                    })
                }
                proxy_protocol::version1::ProxyAddresses::Ipv6 { source, destination } => {
                    Some(ProxyInfo {
                        source_addr: SocketAddr::V6(source),
                        dest_addr: SocketAddr::V6(destination),
                        version: ProxyVersion::V1,
                    })
                }
                proxy_protocol::version1::ProxyAddresses::Unknown => None,
            }
        }
        ProxyHeader::Version2 { addresses, .. } => {
            match addresses {
                proxy_protocol::version2::ProxyAddresses::Ipv4 { source, destination } => {
                    Some(ProxyInfo {
                        source_addr: SocketAddr::V4(source),
                        dest_addr: SocketAddr::V4(destination),
                        version: ProxyVersion::V2,
                    })
                }
                proxy_protocol::version2::ProxyAddresses::Ipv6 { source, destination } => {
                    Some(ProxyInfo {
                        source_addr: SocketAddr::V6(source),
                        dest_addr: SocketAddr::V6(destination),
                        version: ProxyVersion::V2,
                    })
                }
                proxy_protocol::version2::ProxyAddresses::Unspec => None,
                proxy_protocol::version2::ProxyAddresses::Unix { .. } => None,
            }
        }
        _ => None,
    }
}

/// Create a new BufReader with prefix data
fn create_reader_with_prefix<R: AsyncRead + Unpin>(
    inner: BufReader<R>,
    prefix: Vec<u8>,
) -> BufReader<ChainedReader<R>> {
    let inner_stream = inner.into_inner();
    let chained = ChainedReader {
        prefix: if prefix.is_empty() { None } else { Some(prefix) },
        prefix_pos: 0,
        inner: inner_stream,
    };
    BufReader::new(chained)
}

/// A reader that first reads from prefix buffer, then from inner stream
pub struct ChainedReader<R> {
    prefix: Option<Vec<u8>>,
    prefix_pos: usize,
    inner: R,
}

impl<R: AsyncRead + Unpin> AsyncRead for ChainedReader<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = &mut *self;

        // First drain the prefix
        if let Some(ref prefix) = this.prefix {
            if this.prefix_pos < prefix.len() {
                let remaining = &prefix[this.prefix_pos..];
                let to_copy = remaining.len().min(buf.remaining());
                buf.put_slice(&remaining[..to_copy]);
                this.prefix_pos += to_copy;

                if this.prefix_pos >= prefix.len() {
                    this.prefix = None;
                }

                return std::task::Poll::Ready(Ok(()));
            }
        }

        // Then read from inner
        std::pin::Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

/// A wrapper around a TCP stream that handles PROXY protocol parsing
///
/// This wrapper transparently handles PROXY protocol v1 and v2 parsing and provides
/// access to the real client address information while preserving unconsumed data.
pub enum ProxyProtocolStream<T: AsyncRead + Unpin> {
    Plain {
        inner: T,
        proxy_info: Option<ProxyInfo>,
    },
    Buffered {
        inner: BufReader<T>,
        proxy_info: Option<ProxyInfo>,
    },
    ChainedBuffered {
        inner: BufReader<ChainedReader<T>>,
        proxy_info: Option<ProxyInfo>,
    },
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
            let (proxy_info, reader) = parse_proxy_protocol_buffered(stream, timeout_ms).await?;

            // Check if reader is BufReader<T> or BufReader<ChainedReader<T>>
            // This is determined by the parse function
            // For now, we'll use the ChainedBuffered variant as it's more general
            Ok(Self::ChainedBuffered {
                inner: reader,
                proxy_info,
            })
        } else {
            Ok(Self::Plain {
                inner: stream,
                proxy_info: None,
            })
        }
    }

    pub fn proxy_info(&self) -> Option<&ProxyInfo> {
        match self {
            Self::Plain { proxy_info, .. } => proxy_info.as_ref(),
            Self::Buffered { proxy_info, .. } => proxy_info.as_ref(),
            Self::ChainedBuffered { proxy_info, .. } => proxy_info.as_ref(),
        }
    }

    pub fn real_client_addr(&self) -> Option<SocketAddr> {
        self.proxy_info().map(|info| info.source_addr)
    }

    /// Returns true if PROXY protocol was detected and parsed successfully
    pub fn has_proxy_info(&self) -> bool {
        self.proxy_info().is_some()
    }

    /// Extract the inner stream, consuming this wrapper
    /// WARNING: This discards any buffered data that was read during PROXY protocol parsing!
    /// Only use this if you're certain no data was read beyond the PROXY header.
    pub fn inner(self) -> T {
        match self {
            Self::Plain { inner, .. } => inner,
            Self::Buffered { inner, .. } => inner.into_inner(),
            Self::ChainedBuffered { inner, .. } => {
                let chained = inner.into_inner();
                chained.inner
            }
        }
    }
}

// Specific implementation for TcpStream to provide socket methods
impl ProxyProtocolStream<tokio::net::TcpStream> {
    /// Get the peer address from the underlying TCP stream
    pub fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        match self {
            Self::Plain { inner, .. } => inner.peer_addr(),
            Self::Buffered { inner, .. } => inner.get_ref().peer_addr(),
            Self::ChainedBuffered { inner, .. } => {
                inner.get_ref().inner.peer_addr()
            }
        }
    }

    /// Get the local address from the underlying TCP stream
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        match self {
            Self::Plain { inner, .. } => inner.local_addr(),
            Self::Buffered { inner, .. } => inner.get_ref().local_addr(),
            Self::ChainedBuffered { inner, .. } => {
                inner.get_ref().inner.local_addr()
            }
        }
    }

    /// Shutdown the write half of the TCP stream
    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        match self {
            Self::Plain { inner, .. } => inner.shutdown().await,
            Self::Buffered { inner, .. } => inner.get_mut().shutdown().await,
            Self::ChainedBuffered { inner, .. } => {
                inner.get_mut().inner.shutdown().await
            }
        }
    }

    /// Write all bytes to the stream
    pub async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        match self {
            Self::Plain { inner, .. } => inner.write_all(buf).await,
            Self::Buffered { inner, .. } => inner.get_mut().write_all(buf).await,
            Self::ChainedBuffered { inner, .. } => {
                inner.get_mut().inner.write_all(buf).await
            }
        }
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
        match &mut *self {
            Self::Plain { inner, .. } => {
                std::pin::Pin::new(inner).poll_read(cx, buf)
            }
            Self::Buffered { inner, .. } => {
                std::pin::Pin::new(inner).poll_read(cx, buf)
            }
            Self::ChainedBuffered { inner, .. } => {
                std::pin::Pin::new(inner).poll_read(cx, buf)
            }
        }
    }
}

impl<T> AsyncWrite for ProxyProtocolStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Plain { inner, .. } => {
                std::pin::Pin::new(inner).poll_write(cx, buf)
            }
            Self::Buffered { inner, .. } => {
                std::pin::Pin::new(inner.get_mut()).poll_write(cx, buf)
            }
            Self::ChainedBuffered { inner, .. } => {
                std::pin::Pin::new(&mut inner.get_mut().inner).poll_write(cx, buf)
            }
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain { inner, .. } => {
                std::pin::Pin::new(inner).poll_flush(cx)
            }
            Self::Buffered { inner, .. } => {
                std::pin::Pin::new(inner.get_mut()).poll_flush(cx)
            }
            Self::ChainedBuffered { inner, .. } => {
                std::pin::Pin::new(&mut inner.get_mut().inner).poll_flush(cx)
            }
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain { inner, .. } => {
                std::pin::Pin::new(inner).poll_shutdown(cx)
            }
            Self::Buffered { inner, .. } => {
                std::pin::Pin::new(inner.get_mut()).poll_shutdown(cx)
            }
            Self::ChainedBuffered { inner, .. } => {
                std::pin::Pin::new(&mut inner.get_mut().inner).poll_shutdown(cx)
            }
        }
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
        let stream = Cursor::new(header.as_bytes());

        let (result, _reader) = parse_proxy_protocol_buffered(stream, 1000).await.unwrap();

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
        let stream = Cursor::new(header.as_bytes());

        let (result, _reader) = parse_proxy_protocol_buffered(stream, 1000).await.unwrap();

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

        let data = encode(header).unwrap();
        let stream = Cursor::new(data);

        let (result, _reader) = parse_proxy_protocol_buffered(stream, 1000).await.unwrap();

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

        let data = encode(header).unwrap();
        let stream = Cursor::new(data);

        let (result, _reader) = parse_proxy_protocol_buffered(stream, 1000).await.unwrap();

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
        let stream = Cursor::new(&data[..]);

        let (result, mut reader) = parse_proxy_protocol_buffered(stream, 1000).await.unwrap();
        assert!(result.is_none());

        // Verify data is preserved in the reader
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        assert_eq!(&buf[..], &data[..]);
    }

    #[tokio::test]
    async fn test_proxy_protocol_stream_wrapper() {
        // Test the wrapper functionality
        let header = "PROXY TCP4 192.168.1.100 192.168.1.200 12345 80\r\n";
        let http_request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let data = format!("{}{}", header, http_request);
        let stream = Cursor::new(data.into_bytes());

        let mut wrapper = ProxyProtocolStream::new(stream, true, 1000).await.unwrap();

        assert!(wrapper.has_proxy_info());
        assert_eq!(wrapper.real_client_addr().unwrap().ip(), "192.168.1.100".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(wrapper.real_client_addr().unwrap().port(), 12345);

        // Verify HTTP request is still readable
        let mut buf = Vec::new();
        wrapper.read_to_end(&mut buf).await.unwrap();
        assert_eq!(&buf[..], http_request.as_bytes());
    }

    #[tokio::test]
    async fn test_proxy_with_partial_http_data() {
        // Test with PROXY header + partial HTTP data read in one go
        let header = "PROXY TCP4 10.0.0.1 10.0.0.2 55555 443\r\n";
        let http_data = "POST /api HTTP/1.1\r\nContent-Length: 100\r\n\r\n";
        let full_data = format!("{}{}", header, http_data);
        let stream = Cursor::new(full_data.into_bytes());

        let (info, mut reader) = parse_proxy_protocol_buffered(stream, 1000).await.unwrap();

        assert!(info.is_some());
        let proxy_info = info.unwrap();
        assert_eq!(proxy_info.source_addr.ip(), "10.0.0.1".parse::<std::net::IpAddr>().unwrap());

        // Verify HTTP data is preserved
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        assert_eq!(&buf[..], http_data.as_bytes());
    }
}
