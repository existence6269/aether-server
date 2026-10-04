use std::{collections::HashMap, env};

use aether_crypto::IdentityPublicKey;
use async_trait::async_trait;

use crate::{DeviceAddress, ServerError};

/// Authorization policy for a device identity whose challenge signature has
/// already been verified. This trait is not itself an authentication proof.
#[async_trait]
pub trait DeviceAuthorizer: Send + Sync + 'static {
    async fn authorize(
        &self,
        identity: IdentityPublicKey,
        device: &DeviceAddress,
    ) -> Result<(), ServerError>;

    async fn authorize_recipient(&self, device: &DeviceAddress) -> Result<(), ServerError>;
}

/// Provisional exact key/address allowlist. Replace with account/device
/// registration and revocation policy when that system exists.
#[derive(Default)]
pub struct StaticDeviceAuthorizer {
    devices: HashMap<DeviceAddress, IdentityPublicKey>,
}

impl StaticDeviceAuthorizer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(
        &mut self,
        device: DeviceAddress,
        identity: IdentityPublicKey,
    ) -> Result<(), ServerError> {
        device.validate()?;
        self.devices.insert(device, identity);
        Ok(())
    }

    /// Reads semicolon-separated `user_id/device_id=64-hex-public-key` entries.
    pub fn from_env() -> Result<Self, ServerError> {
        let value = match env::var("AETHER_AUTHORIZED_DEVICES") {
            Ok(value) => value,
            Err(env::VarError::NotPresent) => return Ok(Self::new()),
            Err(env::VarError::NotUnicode(_)) => {
                return Err(ServerError::InvalidConfiguration(
                    "AETHER_AUTHORIZED_DEVICES",
                ));
            }
        };
        let mut authorizer = Self::new();
        for entry in value.split(';').filter(|entry| !entry.is_empty()) {
            let (device_text, key_text) =
                entry
                    .split_once('=')
                    .ok_or(ServerError::InvalidConfiguration(
                        "invalid AETHER_AUTHORIZED_DEVICES entry",
                    ))?;
            let (user_id, device_id) =
                device_text
                    .split_once('/')
                    .ok_or(ServerError::InvalidConfiguration(
                        "invalid AETHER_AUTHORIZED_DEVICES address",
                    ))?;
            if key_text.len() != 64 || !key_text.is_ascii() {
                return Err(ServerError::InvalidConfiguration(
                    "device public key must contain 64 hexadecimal characters",
                ));
            }
            let mut key = [0u8; 32];
            for (index, byte) in key.iter_mut().enumerate() {
                let start = index * 2;
                *byte = u8::from_str_radix(&key_text[start..start + 2], 16).map_err(|_| {
                    ServerError::InvalidConfiguration(
                        "device public key must contain hexadecimal characters",
                    )
                })?;
            }
            authorizer.insert(
                DeviceAddress::new(user_id, device_id)?,
                IdentityPublicKey::from_bytes(key),
            )?;
        }
        Ok(authorizer)
    }
}

#[async_trait]
impl DeviceAuthorizer for StaticDeviceAuthorizer {
    async fn authorize(
        &self,
        identity: IdentityPublicKey,
        device: &DeviceAddress,
    ) -> Result<(), ServerError> {
        if self.devices.get(device) == Some(&identity) {
            Ok(())
        } else {
            Err(ServerError::Unauthorized)
        }
    }

    async fn authorize_recipient(&self, device: &DeviceAddress) -> Result<(), ServerError> {
        if self.devices.contains_key(device) {
            Ok(())
        } else {
            Err(ServerError::Unauthorized)
        }
    }
}

/// Deny-all policy used when no provisional device allowlist is configured.
pub struct RejectAllAuthenticator;

#[async_trait]
impl DeviceAuthorizer for RejectAllAuthenticator {
    async fn authorize(
        &self,
        _identity: IdentityPublicKey,
        _device: &DeviceAddress,
    ) -> Result<(), ServerError> {
        Err(ServerError::Unauthorized)
    }

    async fn authorize_recipient(&self, _device: &DeviceAddress) -> Result<(), ServerError> {
        Err(ServerError::Unauthorized)
    }
}
