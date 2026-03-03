use crate::error::{PoCError, PoCResult};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}

/// TCP bridge for communicating with Erlang sbft_rust_bridge
#[derive(Debug)]
pub struct TcpBridge {
    local_addr: SocketAddr,
    erlang_addr: SocketAddr,
    connection: Option<TcpStream>,
    listener: Option<TcpListener>,
    status: ConnectionStatus,
    reconnect_attempts: u32,
    max_reconnect_attempts: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpMessage {
    pub length: u32,
    pub message_type: u8,
    pub payload: Vec<u8>,
}

impl TcpBridge {
    /// Create new TCP bridge
    pub fn new(local_addr: SocketAddr, erlang_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            erlang_addr,
            connection: None,
            listener: None,
            status: ConnectionStatus::Disconnected,
            reconnect_attempts: 0,
            max_reconnect_attempts: 10,
        }
    }

    /// Start TCP bridge as client (connect to Erlang)
    pub async fn start_client(&mut self) -> PoCResult<()> {
        info!("Starting TCP bridge client to {}", self.erlang_addr);

        loop {
            match self.try_connect().await {
                Ok(stream) => {
                    info!("Connected to Erlang BFT layer at {}", self.erlang_addr);
                    self.connection = Some(stream);
                    self.status = ConnectionStatus::Connected;
                    self.reconnect_attempts = 0;
                    break;
                }
                Err(e) => {
                    self.reconnect_attempts += 1;
                    warn!("Connection attempt {} failed: {}", self.reconnect_attempts, e);

                    if self.reconnect_attempts >= self.max_reconnect_attempts {
                        error!("Max reconnection attempts reached");
                        self.status = ConnectionStatus::Error("Max retries exceeded".to_string());
                        return Err(e);
                    }

                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }

        self.start_heartbeat().await;
        Ok(())
    }

    /// Start TCP bridge as server (listen for Erlang connections)
    pub async fn start_server(&mut self) -> PoCResult<()> {
        info!("Starting TCP bridge server on {}", self.local_addr);

        let listener = TcpListener::bind(self.local_addr).await
            .map_err(|e| PoCError::NetworkError(format!("Failed to bind: {}", e)))?;

        info!("TCP bridge listening on {}", self.local_addr);
        self.listener = Some(listener);
        self.status = ConnectionStatus::Connected;

        Ok(())
    }

    /// Accept incoming connection from Erlang
    pub async fn accept_connection(&mut self) -> PoCResult<()> {
        if let Some(ref listener) = self.listener {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!("Accepted connection from {}", addr);
                    self.connection = Some(stream);
                    self.erlang_addr = addr;
                    Ok(())
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                    Err(PoCError::NetworkError(format!("Accept failed: {}", e)))
                }
            }
        } else {
            Err(PoCError::NetworkError("No listener available".to_string()))
        }
    }

    /// Send message to Erlang
    pub async fn send_message(&mut self, message: &TcpMessage) -> PoCResult<()> {
        if let Some(ref mut stream) = self.connection {
            let serialized = Self::serialize_message(message)?;

            stream.write_all(&serialized).await
                .map_err(|e| PoCError::NetworkError(format!("Send failed: {}", e)))?;

            stream.flush().await
                .map_err(|e| PoCError::NetworkError(format!("Flush failed: {}", e)))?;

            debug!("Sent message type {} ({} bytes)", message.message_type, message.length);
            Ok(())
        } else {
            Err(PoCError::NetworkError("No connection available".to_string()))
        }
    }

    /// Receive message from Erlang
    pub async fn receive_message(&mut self) -> PoCResult<TcpMessage> {
        if let Some(ref mut stream) = self.connection {
            // Read message length first (4 bytes)
            let mut length_bytes = [0u8; 4];
            stream.read_exact(&mut length_bytes).await
                .map_err(|e| PoCError::NetworkError(format!("Read length failed: {}", e)))?;

            let length = u32::from_be_bytes(length_bytes);
            if length > 10_000_000 {  // 10MB limit
                return Err(PoCError::NetworkError("Message too large".to_string()));
            }

            // Read message type (1 byte)
            let mut type_byte = [0u8; 1];
            stream.read_exact(&mut type_byte).await
                .map_err(|e| PoCError::NetworkError(format!("Read type failed: {}", e)))?;

            // Read payload
            let mut payload = vec![0u8; (length - 1) as usize];
            stream.read_exact(&mut payload).await
                .map_err(|e| PoCError::NetworkError(format!("Read payload failed: {}", e)))?;

            let message = TcpMessage {
                length,
                message_type: type_byte[0],
                payload,
            };

            debug!("Received message type {} ({} bytes)", message.message_type, length);
            Ok(message)
        } else {
            Err(PoCError::NetworkError("No connection available".to_string()))
        }
    }

    /// Try to establish connection
    async fn try_connect(&mut self) -> PoCResult<TcpStream> {
        self.status = ConnectionStatus::Connecting;

        let stream = TcpStream::connect(self.erlang_addr).await
            .map_err(|e| PoCError::NetworkError(format!("Connect failed: {}", e)))?;

        // Configure socket options
        if let Err(e) = stream.set_nodelay(true) {
            warn!("Failed to set TCP_NODELAY: {}", e);
        }

        Ok(stream)
    }

    /// Start periodic heartbeat
    async fn start_heartbeat(&self) {
        let addr = self.erlang_addr;
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                let heartbeat = TcpMessage {
                    length: 1,
                    message_type: 0, // Heartbeat type
                    payload: vec![],
                };

                debug!("Sending heartbeat to {}", addr);
                // TODO: Send actual heartbeat message
            }
        });
    }

    /// Serialize message for wire protocol
    fn serialize_message(message: &TcpMessage) -> PoCResult<Vec<u8>> {
        let mut buffer = Vec::new();

        // Length (4 bytes, big-endian)
        buffer.extend_from_slice(&message.length.to_be_bytes());

        // Message type (1 byte)
        buffer.push(message.message_type);

        // Payload
        buffer.extend_from_slice(&message.payload);

        Ok(buffer)
    }

    /// Get current connection status
    pub fn status(&self) -> ConnectionStatus {
        self.status.clone()
    }

    /// Close connection
    pub async fn close(&mut self) {
        if let Some(stream) = self.connection.take() {
            drop(stream);
            info!("TCP bridge connection closed");
        }

        if let Some(listener) = self.listener.take() {
            drop(listener);
            info!("TCP bridge listener closed");
        }

        self.status = ConnectionStatus::Disconnected;
    }
}

/// Message types for Erlang communication
pub mod message_types {
    pub const HEARTBEAT: u8 = 0;
    pub const POC_EVENT: u8 = 1;
    pub const DENSITY_EVENT: u8 = 2;
    pub const DAILY_ANCHOR: u8 = 3;
    pub const POREP_EVENT: u8 = 4;
    pub const VALIDATOR_VOTE: u8 = 5;
    pub const SLASHING_REPORT: u8 = 6;
    pub const VRF_REQUEST: u8 = 7;
    pub const VRF_RESPONSE: u8 = 8;
    pub const EPOCH_UPDATE: u8 = 9;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_tcp_bridge_creation() {
        let local_addr = SocketAddr::from_str("127.0.0.1:8080").unwrap();
        let erlang_addr = SocketAddr::from_str("127.0.0.1:8081").unwrap();

        let bridge = TcpBridge::new(local_addr, erlang_addr);
        assert_eq!(bridge.status(), ConnectionStatus::Disconnected);
    }

    #[test]
    fn test_message_serialization() {
        let bridge = TcpBridge::new(
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:8081".parse().unwrap(),
        );

        let message = TcpMessage {
            length: 5,
            message_type: 1,
            payload: b"test".to_vec(),
        };

        let serialized = TcpBridge::serialize_message(&message).unwrap();
        assert_eq!(serialized[0..4], 5u32.to_be_bytes());
        assert_eq!(serialized[4], 1);
        assert_eq!(&serialized[5..], b"test");
    }
}