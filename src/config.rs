use std::{env, net::SocketAddr, time::Duration};

use crate::ServerError;

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub bind_addr: SocketAddr,
    pub server_id: String,
    pub max_connections: usize,
    pub max_known_devices: usize,
    pub max_queued_messages_per_device: usize,
    pub max_queued_messages_total: usize,
    pub max_queued_bytes_per_device: usize,
    pub max_queued_bytes_total: usize,
    pub max_message_bytes: usize,
    pub max_websocket_frame_bytes: usize,
    pub outbound_channel_capacity: usize,
    pub heartbeat_interval: Duration,
    pub heartbeat_timeout: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:8080".parse().expect("valid default bind address"),
            server_id: "aether-server-local".to_owned(),
            max_connections: 10_000,
            max_known_devices: 100_000,
            max_queued_messages_per_device: 1_000,
            max_queued_messages_total: 100_000,
            max_queued_bytes_per_device: 16 * 1024 * 1024,
            max_queued_bytes_total: 512 * 1024 * 1024,
            max_message_bytes: 1024 * 1024,
            max_websocket_frame_bytes: 5 * 1024 * 1024,
            outbound_channel_capacity: 64,
            heartbeat_interval: Duration::from_secs(30),
            heartbeat_timeout: Duration::from_secs(90),
        }
    }
}

impl ServerConfig {
    pub fn from_env() -> Result<Self, ServerError> {
        let defaults = Self::default();
        let bind_addr = env_string("AETHER_BIND_ADDR")?
            .unwrap_or_else(|| defaults.bind_addr.to_string())
            .parse()
            .map_err(|_| ServerError::InvalidConfiguration("AETHER_BIND_ADDR"))?;
        let config = Self {
            bind_addr,
            server_id: env_string("AETHER_SERVER_ID")?
                .unwrap_or_else(|| defaults.server_id.clone()),
            max_connections: env_usize("AETHER_MAX_CONNECTIONS", defaults.max_connections)?,
            max_known_devices: env_usize("AETHER_MAX_KNOWN_DEVICES", defaults.max_known_devices)?,
            max_queued_messages_per_device: env_usize(
                "AETHER_MAX_QUEUED_MESSAGES_PER_DEVICE",
                defaults.max_queued_messages_per_device,
            )?,
            max_queued_messages_total: env_usize(
                "AETHER_MAX_QUEUED_MESSAGES_TOTAL",
                defaults.max_queued_messages_total,
            )?,
            max_queued_bytes_per_device: env_usize(
                "AETHER_MAX_QUEUED_BYTES_PER_DEVICE",
                defaults.max_queued_bytes_per_device,
            )?,
            max_queued_bytes_total: env_usize(
                "AETHER_MAX_QUEUED_BYTES_TOTAL",
                defaults.max_queued_bytes_total,
            )?,
            max_message_bytes: env_usize("AETHER_MAX_MESSAGE_BYTES", defaults.max_message_bytes)?,
            max_websocket_frame_bytes: env_usize(
                "AETHER_MAX_WEBSOCKET_FRAME_BYTES",
                defaults.max_websocket_frame_bytes,
            )?,
            outbound_channel_capacity: env_usize(
                "AETHER_OUTBOUND_CHANNEL_CAPACITY",
                defaults.outbound_channel_capacity,
            )?,
            heartbeat_interval: Duration::from_secs(env_u64(
                "AETHER_HEARTBEAT_INTERVAL_SECS",
                defaults.heartbeat_interval.as_secs(),
            )?),
            heartbeat_timeout: Duration::from_secs(env_u64(
                "AETHER_HEARTBEAT_TIMEOUT_SECS",
                defaults.heartbeat_timeout.as_secs(),
            )?),
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ServerError> {
        let min_frame_bytes = self
            .max_message_bytes
            .checked_mul(4)
            .and_then(|size| size.checked_add(1024))
            .ok_or(ServerError::InvalidConfiguration(
                "message size limit is too large",
            ))?;
        if self.max_connections == 0
            || self.server_id.is_empty()
            || self.server_id.len() > 256
            || self.max_known_devices == 0
            || self.max_queued_messages_per_device == 0
            || self.max_queued_messages_total == 0
            || self.max_queued_bytes_per_device == 0
            || self.max_queued_bytes_total == 0
            || self.max_message_bytes == 0
            || self.max_websocket_frame_bytes < min_frame_bytes
            || self.outbound_channel_capacity == 0
            || self.heartbeat_interval.is_zero()
            || self.heartbeat_timeout <= self.heartbeat_interval
        {
            return Err(ServerError::InvalidConfiguration(
                "limits must be positive and heartbeat timeout must exceed interval",
            ));
        }
        Ok(())
    }
}

fn env_string(name: &str) -> Result<Option<String>, ServerError> {
    match env::var(name) {
        Ok(value) if value.is_empty() => Err(ServerError::InvalidConfiguration(
            "environment value must not be empty",
        )),
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(ServerError::InvalidConfiguration(
            "environment value is not Unicode",
        )),
    }
}

fn env_usize(name: &str, default: usize) -> Result<usize, ServerError> {
    env_string(name)?
        .map(|value| {
            value
                .parse()
                .map_err(|_| ServerError::InvalidConfiguration("invalid integer environment value"))
        })
        .unwrap_or(Ok(default))
}

fn env_u64(name: &str, default: u64) -> Result<u64, ServerError> {
    env_string(name)?
        .map(|value| {
            value
                .parse()
                .map_err(|_| ServerError::InvalidConfiguration("invalid integer environment value"))
        })
        .unwrap_or(Ok(default))
}

#[cfg(test)]
mod tests {
    use super::ServerConfig;

    #[test]
    fn rejects_invalid_resource_and_heartbeat_limits() {
        let mut config = ServerConfig::default();
        config.max_queued_messages_total = 0;
        assert!(config.validate().is_err());

        let mut config = ServerConfig::default();
        config.heartbeat_timeout = config.heartbeat_interval;
        assert!(config.validate().is_err());
    }
}
