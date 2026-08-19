use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{sync_merge::MergeOperation, sync_recovery::DeviceRegistry};

const FORMAT_VERSION: u32 = 1;
const DOMAIN: &[u8] = b"VPSHELL-SYNC-OPERATION-SIGNATURE-V1";
const KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const MAX_ENCODED_BYTES: usize = 1_500_000;

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SignedOperationEnvelope {
    format_version: u32,
    operation: String,
    signer_public_key: String,
    signature: String,
}

impl SignedOperationEnvelope {
    pub(crate) fn sign(
        operation: &MergeOperation,
        signing_key: &DeviceSigningKey,
    ) -> Result<Self, String> {
        let operation_bytes = operation
            .encode()
            .map_err(|_| "无法编码待签名同步 operation".to_string())?;
        let public_key = signing_key.public_key();
        let signature = signing_key.sign_message(operation.device_id(), &operation_bytes);
        Ok(Self {
            format_version: FORMAT_VERSION,
            operation: URL_SAFE_NO_PAD.encode(operation_bytes),
            signer_public_key: URL_SAFE_NO_PAD.encode(public_key),
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate_shape()?;
        let encoded =
            serde_json::to_vec(self).map_err(|_| "无法序列化签名同步 operation".to_string())?;
        if encoded.len() > MAX_ENCODED_BYTES {
            return Err("签名同步 operation 超过 1.5 MiB".to_string());
        }
        Ok(encoded)
    }

    pub(crate) fn decode(encoded: &[u8]) -> Result<Self, String> {
        if encoded.is_empty() || encoded.len() > MAX_ENCODED_BYTES {
            return Err("签名同步 operation 为空或超过 1.5 MiB".to_string());
        }
        let envelope: Self = serde_json::from_slice(encoded)
            .map_err(|_| "签名同步 operation JSON 损坏或字段不受支持".to_string())?;
        envelope.validate_shape()?;
        Ok(envelope)
    }

    pub(crate) fn verify(&self, registry: &DeviceRegistry) -> Result<MergeOperation, String> {
        self.validate_shape()?;
        let operation_bytes = decode_bounded(&self.operation, 1, 1_100_000, "签名 operation")?;
        let operation = MergeOperation::decode(&operation_bytes)
            .map_err(|_| "签名同步 operation 内容无效".to_string())?;
        let public_key = decode_exact::<KEY_BYTES>(&self.signer_public_key, "设备签名公钥")?;
        let expected_key = registry
            .public_signing_key(operation.device_id())
            .map_err(|_| "签名设备未登记或已撤销".to_string())?;
        if expected_key != public_key {
            return Err("签名设备公钥与 registry 不匹配".to_string());
        }
        self.verify_with_public_key(&operation, &operation_bytes, &public_key)?;
        Ok(operation)
    }

    pub(crate) fn verify_self(&self) -> Result<MergeOperation, String> {
        self.validate_shape()?;
        let operation_bytes = decode_bounded(&self.operation, 1, 1_100_000, "签名 operation")?;
        let operation = MergeOperation::decode(&operation_bytes)
            .map_err(|_| "签名同步 operation 内容无效".to_string())?;
        let public_key = decode_exact::<KEY_BYTES>(&self.signer_public_key, "设备签名公钥")?;
        self.verify_with_public_key(&operation, &operation_bytes, &public_key)?;
        Ok(operation)
    }

    fn validate_shape(&self) -> Result<(), String> {
        if self.format_version != FORMAT_VERSION {
            return Err("签名同步 operation 版本不受支持".to_string());
        }
        decode_bounded(&self.operation, 1, 1_100_000, "签名 operation")?;
        decode_exact::<KEY_BYTES>(&self.signer_public_key, "设备签名公钥")?;
        decode_exact::<SIGNATURE_BYTES>(&self.signature, "设备 operation 签名")?;
        Ok(())
    }

    fn verify_with_public_key(
        &self,
        operation: &MergeOperation,
        operation_bytes: &[u8],
        public_key: &[u8],
    ) -> Result<(), String> {
        let public_key: [u8; KEY_BYTES] = public_key
            .try_into()
            .map_err(|_| "设备签名公钥长度无效".to_string())?;
        let signature_bytes =
            decode_exact::<SIGNATURE_BYTES>(&self.signature, "设备 operation 签名")?;
        let signature = Signature::from_bytes(
            &signature_bytes
                .try_into()
                .map_err(|_| "设备 operation 签名长度无效".to_string())?,
        );
        let verifying_key =
            VerifyingKey::from_bytes(&public_key).map_err(|_| "设备签名公钥无效".to_string())?;
        let message = signature_message(operation.device_id(), operation_bytes);
        verifying_key
            .verify_strict(&message, &signature)
            .map_err(|_| "设备 operation 签名验证失败".to_string())
    }
}

pub(crate) struct DeviceSigningKey(Zeroizing<[u8; KEY_BYTES]>);

impl DeviceSigningKey {
    pub(crate) fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(crate) fn load_or_create(device_id: &str) -> Result<Self, String> {
        validate_device_id(device_id)?;
        #[cfg(test)]
        {
            let mut digest = Sha256::new();
            digest.update(b"vpshell-test-device-signing-key-v1");
            digest.update(device_id.as_bytes());
            return Ok(Self::from_bytes(digest.finalize().into()));
        }
        #[cfg(not(test))]
        {
            let username = format!("device-signing-{device_id}");
            let entry = keyring::Entry::new("com.sanro.vpshell.sync-signing", &username)
                .map_err(|_| "无法打开设备签名系统凭据条目".to_string())?;
            match entry.get_password() {
                Ok(encoded) => {
                    let encoded = Zeroizing::new(encoded);
                    Ok(Self::from_bytes(decode_exact::<KEY_BYTES>(
                        encoded.as_str(),
                        "设备签名私钥",
                    )?))
                }
                Err(keyring::Error::NoEntry) => {
                    let mut bytes = Zeroizing::new([0_u8; KEY_BYTES]);
                    getrandom::fill(&mut *bytes)
                        .map_err(|_| "无法从操作系统安全随机源生成设备签名私钥".to_string())?;
                    let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_ref()));
                    entry
                        .set_password(encoded.as_str())
                        .map_err(|_| "无法保存设备签名私钥到系统凭据管理器".to_string())?;
                    Ok(Self::from_bytes(*bytes))
                }
                Err(_) => Err("无法读取设备签名系统凭据".to_string()),
            }
        }
    }

    pub(crate) fn public_key(&self) -> [u8; KEY_BYTES] {
        use ed25519_dalek::SigningKey;

        SigningKey::from_bytes(&self.0).verifying_key().to_bytes()
    }

    pub(crate) fn sign(
        &self,
        operation: &MergeOperation,
    ) -> Result<SignedOperationEnvelope, String> {
        SignedOperationEnvelope::sign(operation, self)
    }

    fn sign_message(&self, device_id: &str, operation_bytes: &[u8]) -> Signature {
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(&self.0);
        signing_key.sign(&signature_message(device_id, operation_bytes))
    }
}

pub(crate) fn decode_signed_or_legacy_operation(encoded: &[u8]) -> Result<MergeOperation, String> {
    match SignedOperationEnvelope::decode(encoded) {
        Ok(envelope) => envelope.verify_self(),
        Err(_) => {
            MergeOperation::decode(encoded).map_err(|_| "同步 operation 无法验证或解析".to_string())
        }
    }
}

fn signature_message(device_id: &str, operation_bytes: &[u8]) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(DOMAIN.len() + device_id.len() + operation_bytes.len() + 16);
    message.extend_from_slice(DOMAIN);
    push_field(&mut message, device_id.as_bytes());
    push_field(&mut message, operation_bytes);
    message
}

fn push_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn validate_device_id(device_id: &str) -> Result<(), String> {
    let parsed =
        uuid::Uuid::parse_str(device_id).map_err(|_| "设备 ID 必须是规范 UUID".to_string())?;
    if parsed.to_string() != device_id {
        return Err("设备 ID 必须是小写规范 UUID".to_string());
    }
    Ok(())
}

fn decode_exact<const N: usize>(encoded: &str, label: &str) -> Result<[u8; N], String> {
    if encoded.is_empty() {
        return Err(format!("{label} 编码长度无效"));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| format!("{label} 不是规范 base64url"))?;
    if decoded.len() != N || URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(format!("{label} 长度或编码不规范"));
    }
    decoded.try_into().map_err(|_| format!("{label} 长度无效"))
}

fn decode_bounded(
    encoded: &str,
    minimum: usize,
    maximum: usize,
    label: &str,
) -> Result<Vec<u8>, String> {
    let maximum_encoded = maximum.saturating_add(2) / 3 * 4;
    if encoded.is_empty() || encoded.len() > maximum_encoded {
        return Err(format!("{label} 编码长度无效"));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| format!("{label} 不是规范 base64url"))?;
    if !(minimum..=maximum).contains(&decoded.len()) || URL_SAFE_NO_PAD.encode(&decoded) != encoded
    {
        return Err(format!("{label} 长度或编码不规范"));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync_merge::MergeOperation;

    const VAULT_ID: &str = "11111111-2222-4333-8444-555555555555";
    const DEVICE_A: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    const DEVICE_B: &str = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff";

    fn operation(device_id: &str) -> MergeOperation {
        serde_json::from_value(serde_json::json!({
            "formatVersion": 1,
            "operationId": "33333333-3333-4333-8333-333333333333",
            "deviceId": device_id,
            "sequence": 1,
            "hlc": {"physicalMs": 1, "logical": 0},
            "payload": {
                "kind": "patch",
                "payload": {
                    "entityKind": "setting",
                    "entityId": "setting-font",
                    "fields": {"fontSize": {"type": "integer", "value": 14}},
                    "observedFields": {"fontSize": null},
                    "observedTombstone": null
                }
            }
        }))
        .unwrap()
    }

    #[test]
    fn signed_operation_round_trips_and_registry_verifies_active_device() {
        let signer = DeviceSigningKey::from_bytes([7; KEY_BYTES]);
        let operation = operation(DEVICE_A);
        let envelope = signer.sign(&operation).unwrap();
        let encoded = envelope.encode().unwrap();
        assert_eq!(
            decode_signed_or_legacy_operation(&encoded).unwrap(),
            operation
        );
        let registry =
            DeviceRegistry::new(VAULT_ID, DEVICE_A, "Laptop", &signer.public_key(), 1).unwrap();
        assert_eq!(envelope.verify(&registry).unwrap(), operation);
    }

    #[test]
    fn signature_tampering_wrong_registry_and_revocation_fail_closed() {
        let signer = DeviceSigningKey::from_bytes([8; KEY_BYTES]);
        let original = operation(DEVICE_A);
        let mut envelope = signer.sign(&original).unwrap();
        let registry =
            DeviceRegistry::new(VAULT_ID, DEVICE_A, "Laptop", &signer.public_key(), 1).unwrap();
        envelope.signature = URL_SAFE_NO_PAD.encode([0; SIGNATURE_BYTES]);
        assert!(envelope.verify(&registry).is_err());

        let mut tampered_operation = signer.sign(&original).unwrap();
        tampered_operation.operation =
            URL_SAFE_NO_PAD.encode(operation(DEVICE_B).encode().unwrap());
        assert!(tampered_operation.verify_self().is_err());

        let signer_b = DeviceSigningKey::from_bytes([9; KEY_BYTES]);
        let wrong_registry =
            DeviceRegistry::new(VAULT_ID, DEVICE_A, "Laptop", &signer_b.public_key(), 1).unwrap();
        let valid = signer.sign(&original).unwrap();
        assert!(valid.verify(&wrong_registry).is_err());

        let mut revoked =
            DeviceRegistry::new(VAULT_ID, DEVICE_A, "Laptop", &signer.public_key(), 1).unwrap();
        revoked
            .add_device(1, DEVICE_B, "Phone", &signer_b.public_key(), 2)
            .unwrap();
        revoked
            .revoke_device(
                2,
                DEVICE_A,
                crate::sync_recovery::RevocationReason::Compromised,
                3,
            )
            .unwrap();
        assert!(valid.verify(&revoked).is_err());
    }

    #[test]
    fn legacy_operation_decoding_remains_explicit_and_unknown_fields_are_rejected() {
        let operation = operation(DEVICE_A);
        let encoded = operation.encode().unwrap();
        assert_eq!(
            decode_signed_or_legacy_operation(&encoded).unwrap(),
            operation
        );
        let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        value["unknown"] = serde_json::json!(true);
        assert!(decode_signed_or_legacy_operation(&serde_json::to_vec(&value).unwrap()).is_err());

        let signed = DeviceSigningKey::from_bytes([7; KEY_BYTES])
            .sign(&operation)
            .unwrap()
            .encode()
            .unwrap();
        let mut signed_value: serde_json::Value = serde_json::from_slice(&signed).unwrap();
        signed_value["unknown"] = serde_json::json!(true);
        assert!(
            SignedOperationEnvelope::decode(&serde_json::to_vec(&signed_value).unwrap()).is_err()
        );
        let mut signed_value: serde_json::Value = serde_json::from_slice(&signed).unwrap();
        let key = signed_value["signerPublicKey"]
            .as_str()
            .unwrap()
            .to_string();
        signed_value["signerPublicKey"] = serde_json::json!(format!("{key}="));
        assert!(
            SignedOperationEnvelope::decode(&serde_json::to_vec(&signed_value).unwrap()).is_err()
        );
    }
}
