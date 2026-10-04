use aether_crypto::{DeviceAuthChallenge, DeviceAuthProof, IdentityPublicKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ServerError;

const MAX_ADDRESS_PART_BYTES: usize = 128;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAddress {
    pub user_id: String,
    pub device_id: String,
}

impl DeviceAddress {
    pub fn new(
        user_id: impl Into<String>,
        device_id: impl Into<String>,
    ) -> Result<Self, ServerError> {
        let address = Self {
            user_id: user_id.into(),
            device_id: device_id.into(),
        };
        address.validate()?;
        Ok(address)
    }

    pub fn validate(&self) -> Result<(), ServerError> {
        for part in [&self.user_id, &self.device_id] {
            if part.is_empty()
                || part.len() > MAX_ADDRESS_PART_BYTES
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            {
                return Err(ServerError::InvalidRequest);
            }
        }
        Ok(())
    }
}

/// An opaque ciphertext envelope. The relay uses only endpoint and ID metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpaqueEnvelope {
    pub message_id: Uuid,
    pub sender: DeviceAddress,
    pub recipient: DeviceAddress,
    pub payload: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientFrame {
    Send { to: DeviceAddress, payload: Vec<u8> },
    Ack { message_id: Uuid },
    Pong { nonce: Uuid },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthClientFrame {
    Start {
        device: DeviceAddress,
        identity_key: IdentityPublicKey,
    },
    Proof {
        challenge_id: [u8; 16],
        proof: DeviceAuthProof,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthServerFrame {
    Challenge { challenge: DeviceAuthChallenge },
    Authenticated { device: DeviceAddress },
    Rejected { code: String },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerFrame {
    Accepted { message_id: Uuid },
    Deliver { envelope: OpaqueEnvelope },
    Ping { nonce: Uuid },
    Error { code: String },
}

pub(crate) fn parse_client_frame(
    encoded: &[u8],
    max_frame_bytes: usize,
    max_message_bytes: usize,
) -> Result<ClientFrame, ServerError> {
    if encoded.len() > max_frame_bytes {
        return Err(ServerError::MessageTooLarge);
    }
    let frame: ClientFrame =
        serde_json::from_slice(encoded).map_err(|_| ServerError::InvalidRequest)?;
    match &frame {
        ClientFrame::Send { to, payload } => {
            to.validate()?;
            if payload.len() > max_message_bytes {
                return Err(ServerError::MessageTooLarge);
            }
        }
        ClientFrame::Ack { .. } | ClientFrame::Pong { .. } => {}
    }
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::{parse_client_frame, DeviceAddress};
    use crate::ServerError;

    #[test]
    fn device_address_validation_is_bounded_and_unambiguous() {
        assert!(DeviceAddress::new("account-7", "phone_2").is_ok());
        assert!(DeviceAddress::new("", "phone").is_err());
        assert!(DeviceAddress::new("account/7", "phone").is_err());
        assert!(DeviceAddress::new("u".repeat(129), "phone").is_err());
    }

    #[test]
    fn rejects_malformed_and_oversized_client_envelopes() {
        assert!(matches!(
            parse_client_frame(b"{", 128, 8),
            Err(ServerError::InvalidRequest)
        ));
        assert!(matches!(
            parse_client_frame(
                br#"{"type":"send","to":{"user_id":"bob","device_id":"phone"},"payload":[1,2,3]}"#,
                128,
                2
            ),
            Err(ServerError::MessageTooLarge)
        ));
    }
}
