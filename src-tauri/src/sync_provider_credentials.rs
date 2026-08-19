use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::CREDENTIAL_SERVICE;

pub(crate) const WEBDAV_CREDENTIAL_PREFIX: &str = "sync-webdav-";
pub(crate) const S3_CREDENTIAL_PREFIX: &str = "sync-s3-";
pub(crate) const GATEWAY_CREDENTIAL_PREFIX: &str = "sync-gateway-";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StoreWebDavCredentialRequest {
    password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StoreS3CredentialRequest {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StoreGatewayCredentialRequest {
    password: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredS3Credential {
    version: u8,
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
}

pub(crate) struct S3Credentials {
    access_key_id: Zeroizing<String>,
    secret_access_key: Zeroizing<String>,
    session_token: Option<Zeroizing<String>>,
}

impl S3Credentials {
    pub(crate) fn new(
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
    ) -> Result<Self, String> {
        let access_key_id = Zeroizing::new(access_key_id);
        let secret_access_key = Zeroizing::new(secret_access_key);
        let session_token = session_token
            .filter(|value| !value.is_empty())
            .map(Zeroizing::new);
        validate_s3_credentials(
            access_key_id.as_str(),
            secret_access_key.as_str(),
            session_token.as_deref().map(|value| value.as_str()),
        )?;
        Ok(Self {
            access_key_id,
            secret_access_key,
            session_token,
        })
    }

    pub(crate) fn access_key_id(&self) -> &str {
        self.access_key_id.as_str()
    }

    pub(crate) fn secret_access_key(&self) -> &str {
        self.secret_access_key.as_str()
    }

    pub(crate) fn session_token(&self) -> Option<&str> {
        self.session_token.as_deref().map(|value| value.as_str())
    }
}

pub(crate) fn store_webdav_credential(
    request: StoreWebDavCredentialRequest,
) -> Result<String, String> {
    let password = Zeroizing::new(request.password);
    validate_webdav_password(password.as_bytes())?;
    let reference = format!("{WEBDAV_CREDENTIAL_PREFIX}{}", uuid::Uuid::new_v4());
    keyring::Entry::new(CREDENTIAL_SERVICE, &reference)
        .and_then(|entry| entry.set_password(password.as_str()))
        .map_err(|_| "无法把 WebDAV 密码保存到系统凭据管理器".to_string())?;
    Ok(reference)
}

pub(crate) fn store_s3_credential(request: StoreS3CredentialRequest) -> Result<String, String> {
    let credentials = S3Credentials::new(
        request.access_key_id,
        request.secret_access_key,
        request.session_token,
    )?;
    let mut stored = StoredS3Credential {
        version: 1,
        access_key_id: credentials.access_key_id().to_string(),
        secret_access_key: credentials.secret_access_key().to_string(),
        session_token: credentials.session_token().map(str::to_string),
    };
    let encoded = Zeroizing::new(
        serde_json::to_string(&stored).map_err(|_| "无法编码 S3 系统凭据".to_string())?,
    );
    stored.access_key_id.zeroize();
    stored.secret_access_key.zeroize();
    if let Some(token) = &mut stored.session_token {
        token.zeroize();
    }
    let reference = format!("{S3_CREDENTIAL_PREFIX}{}", uuid::Uuid::new_v4());
    keyring::Entry::new(CREDENTIAL_SERVICE, &reference)
        .and_then(|entry| entry.set_password(encoded.as_str()))
        .map_err(|_| "无法把 S3 凭据保存到系统凭据管理器".to_string())?;
    Ok(reference)
}

pub(crate) fn store_gateway_credential(
    request: StoreGatewayCredentialRequest,
) -> Result<String, String> {
    let password = Zeroizing::new(request.password);
    validate_gateway_password(password.as_bytes())?;
    let reference = format!("{GATEWAY_CREDENTIAL_PREFIX}{}", uuid::Uuid::new_v4());
    keyring::Entry::new(CREDENTIAL_SERVICE, &reference)
        .and_then(|entry| entry.set_password(password.as_str()))
        .map_err(|_| "无法把 Gateway 密码保存到系统凭据管理器".to_string())?;
    Ok(reference)
}

pub(crate) fn read_webdav_credential(reference: &str) -> Result<Zeroizing<String>, String> {
    validate_webdav_credential_reference(reference)?;
    let secret = keyring::Entry::new(CREDENTIAL_SERVICE, reference)
        .map_err(|_| "无法访问系统凭据管理器".to_string())?
        .get_password()
        .map_err(|_| "未找到已保存的 WebDAV 凭据".to_string())?;
    let secret = Zeroizing::new(secret);
    validate_webdav_password(secret.as_bytes())?;
    Ok(secret)
}

pub(crate) fn read_s3_credential(reference: &str) -> Result<S3Credentials, String> {
    validate_s3_credential_reference(reference)?;
    let encoded = Zeroizing::new(
        keyring::Entry::new(CREDENTIAL_SERVICE, reference)
            .map_err(|_| "无法访问系统凭据管理器".to_string())?
            .get_password()
            .map_err(|_| "未找到已保存的 S3 凭据".to_string())?,
    );
    let mut stored: StoredS3Credential = serde_json::from_str(encoded.as_str())
        .map_err(|_| "已保存的 S3 凭据格式无效".to_string())?;
    if stored.version != 1 {
        stored.access_key_id.zeroize();
        stored.secret_access_key.zeroize();
        if let Some(token) = &mut stored.session_token {
            token.zeroize();
        }
        return Err("已保存的 S3 凭据版本不受支持".to_string());
    }
    S3Credentials::new(
        stored.access_key_id,
        stored.secret_access_key,
        stored.session_token,
    )
}

pub(crate) fn read_gateway_credential(reference: &str) -> Result<Zeroizing<String>, String> {
    validate_gateway_credential_reference(reference)?;
    let secret = keyring::Entry::new(CREDENTIAL_SERVICE, reference)
        .map_err(|_| "无法访问系统凭据管理器".to_string())?
        .get_password()
        .map_err(|_| "未找到已保存的 Gateway 凭据".to_string())?;
    let secret = Zeroizing::new(secret);
    validate_gateway_password(secret.as_bytes())?;
    Ok(secret)
}

pub(crate) fn validate_webdav_credential_reference(reference: &str) -> Result<(), String> {
    if reference.len() > 128
        || !reference.starts_with(WEBDAV_CREDENTIAL_PREFIX)
        || !reference
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, '-' | '_'))
    {
        return Err("WebDAV 凭据引用无效".to_string());
    }
    let identifier = reference
        .strip_prefix(WEBDAV_CREDENTIAL_PREFIX)
        .ok_or_else(|| "WebDAV 凭据引用无效".to_string())?;
    uuid::Uuid::parse_str(identifier).map_err(|_| "WebDAV 凭据引用无效".to_string())?;
    Ok(())
}

pub(crate) fn validate_s3_credential_reference(reference: &str) -> Result<(), String> {
    validate_reference(reference, S3_CREDENTIAL_PREFIX, "S3")
}

pub(crate) fn validate_gateway_credential_reference(reference: &str) -> Result<(), String> {
    validate_reference(reference, GATEWAY_CREDENTIAL_PREFIX, "Gateway")
}

pub(crate) fn validate_sync_provider_credential_reference(reference: &str) -> Result<(), String> {
    if reference.starts_with(WEBDAV_CREDENTIAL_PREFIX) {
        validate_webdav_credential_reference(reference)
    } else if reference.starts_with(GATEWAY_CREDENTIAL_PREFIX) {
        validate_gateway_credential_reference(reference)
    } else {
        validate_s3_credential_reference(reference)
    }
}

fn validate_reference(reference: &str, prefix: &str, label: &str) -> Result<(), String> {
    if reference.len() > 128
        || !reference.starts_with(prefix)
        || !reference
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, '-' | '_'))
    {
        return Err(format!("{label} 凭据引用无效"));
    }
    let identifier = reference
        .strip_prefix(prefix)
        .ok_or_else(|| format!("{label} 凭据引用无效"))?;
    uuid::Uuid::parse_str(identifier).map_err(|_| format!("{label} 凭据引用无效"))?;
    Ok(())
}

fn validate_s3_credentials(
    access_key_id: &str,
    secret_access_key: &str,
    session_token: Option<&str>,
) -> Result<(), String> {
    if access_key_id.is_empty()
        || access_key_id.len() > 128
        || !access_key_id
            .bytes()
            .all(|value| value.is_ascii_alphanumeric())
        || secret_access_key.is_empty()
        || secret_access_key.len() > 1_024
        || !secret_access_key
            .bytes()
            .all(|value| value.is_ascii_graphic())
        || session_token.is_some_and(|token| {
            token.is_empty()
                || token.len() > 4_096
                || !token.bytes().all(|value| value.is_ascii_graphic())
        })
    {
        return Err("S3 凭据字段超出限制".to_string());
    }
    Ok(())
}

fn validate_webdav_password(password: &[u8]) -> Result<(), String> {
    if password.is_empty() || password.len() > 1_024 || password.contains(&0) {
        return Err("WebDAV 密码必须为 1 至 1024 字节且不能包含 NUL".to_string());
    }
    Ok(())
}

fn validate_gateway_password(password: &[u8]) -> Result<(), String> {
    if password.is_empty() || password.len() > 1_024 || password.contains(&0) {
        return Err("Gateway 密码必须为 1 至 1024 字节且不能包含 NUL".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webdav_credential_reference_and_password_are_strictly_bounded() {
        let reference = format!("{WEBDAV_CREDENTIAL_PREFIX}{}", uuid::Uuid::new_v4());
        assert!(validate_webdav_credential_reference(&reference).is_ok());
        for invalid in [
            "ssh-00000000-0000-0000-0000-000000000000",
            "sync-webdav-not-a-uuid",
            "sync-webdav-00000000-0000-0000-0000-000000000000/escape",
        ] {
            assert!(validate_webdav_credential_reference(invalid).is_err());
        }
        assert!(validate_webdav_password(b"").is_err());
        assert!(validate_webdav_password(&vec![b'x'; 1_025]).is_err());
        assert!(validate_webdav_password(b"contains\0nul").is_err());
        assert!(validate_webdav_password(b"valid-password").is_ok());
    }

    #[test]
    fn s3_credential_fields_and_references_are_strictly_bounded() {
        let reference = format!("{S3_CREDENTIAL_PREFIX}{}", uuid::Uuid::new_v4());
        assert!(validate_s3_credential_reference(&reference).is_ok());
        assert!(validate_sync_provider_credential_reference(&reference).is_ok());
        assert!(
            validate_sync_provider_credential_reference(&format!(
                "{WEBDAV_CREDENTIAL_PREFIX}{}",
                uuid::Uuid::new_v4()
            ))
            .is_ok()
        );
        for invalid in [
            "sync-s3-not-a-uuid",
            "sync-s3-00000000-0000-0000-0000-000000000000/escape",
            "ssh-00000000-0000-0000-0000-000000000000",
        ] {
            assert!(validate_s3_credential_reference(invalid).is_err());
        }
        assert!(S3Credentials::new("".into(), "secret".into(), None).is_err());
        assert!(S3Credentials::new("access".into(), "".into(), None).is_err());
        assert!(S3Credentials::new("access".into(), "line\nbreak".into(), None).is_err());
        assert!(
            S3Credentials::new("access".into(), "secret".into(), Some("line\nbreak".into()))
                .is_err()
        );
        let valid = S3Credentials::new(
            "access".into(),
            "secret".into(),
            Some("session-token".into()),
        )
        .unwrap();
        assert_eq!(valid.access_key_id(), "access");
        assert_eq!(valid.session_token(), Some("session-token"));
    }

    #[test]
    fn gateway_credential_reference_and_password_are_strictly_bounded() {
        let reference = format!("{GATEWAY_CREDENTIAL_PREFIX}{}", uuid::Uuid::new_v4());
        assert!(validate_gateway_credential_reference(&reference).is_ok());
        assert!(validate_sync_provider_credential_reference(&reference).is_ok());
        for invalid in [
            "sync-gateway-not-a-uuid",
            "sync-gateway-00000000-0000-0000-0000-000000000000/escape",
            "sync-s3-00000000-0000-0000-0000-000000000000",
        ] {
            assert!(validate_gateway_credential_reference(invalid).is_err());
        }
        assert!(validate_gateway_password(b"").is_err());
        assert!(validate_gateway_password(&vec![b'x'; 1_025]).is_err());
        assert!(validate_gateway_password(b"contains\0nul").is_err());
        assert!(validate_gateway_password(b"valid-password").is_ok());
    }
}
