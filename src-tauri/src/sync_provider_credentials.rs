use serde::Deserialize;
use zeroize::Zeroizing;

use crate::CREDENTIAL_SERVICE;

pub(crate) const WEBDAV_CREDENTIAL_PREFIX: &str = "sync-webdav-";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StoreWebDavCredentialRequest {
    password: String,
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

fn validate_webdav_password(password: &[u8]) -> Result<(), String> {
    if password.is_empty() || password.len() > 1_024 || password.contains(&0) {
        return Err("WebDAV 密码必须为 1 至 1024 字节且不能包含 NUL".to_string());
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
}
