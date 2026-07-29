use std::{fs, path::Path};

use serde::{Deserialize, Serialize};
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey, rand_core::OsRng};
use zeroize::Zeroizing;

use crate::CREDENTIAL_SERVICE;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GenerateKeyRequest {
    algorithm: String,
    path: String,
    comment: String,
    passphrase: String,
    save_passphrase: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GeneratedKey {
    id: String,
    name: String,
    algorithm: String,
    private_key_path: String,
    public_key_path: String,
    fingerprint: String,
    passphrase_ref: Option<String>,
}

pub(crate) fn generate_key(request: GenerateKeyRequest) -> Result<GeneratedKey, String> {
    let path = Path::new(&request.path);
    if !path.is_absolute() {
        return Err("私钥路径必须是绝对路径".to_string());
    }
    if path.exists() {
        return Err("目标私钥文件已经存在".to_string());
    }
    let public_path = format!("{}.pub", path.display());
    if Path::new(&public_path).exists() {
        return Err("目标公钥文件已经存在".to_string());
    }
    if request.comment.len() > 160
        || request.comment.contains(['\r', '\n', '\0'])
        || request.passphrase.contains(['\r', '\n', '\0'])
    {
        return Err("密钥注释或口令包含不支持的字符".to_string());
    }
    if !request.passphrase.is_empty() && request.passphrase.chars().count() < 10 {
        return Err("私钥口令至少需要 10 个字符".to_string());
    }

    let algorithm = match request.algorithm.as_str() {
        "ed25519" => Algorithm::Ed25519,
        "rsa4096" => Algorithm::Rsa { hash: None },
        _ => return Err("不支持的 SSH 密钥算法".to_string()),
    };

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("无法创建密钥目录: {error}"))?;
    }

    let mut rng = OsRng;
    let mut private_key = PrivateKey::random(&mut rng, algorithm)
        .map_err(|error| format!("生成密钥失败: {error}"))?;
    private_key.set_comment(request.comment.trim().to_string());
    let fingerprint = private_key.fingerprint(HashAlg::Sha256).to_string();
    let passphrase = Zeroizing::new(request.passphrase);
    let private_to_write = if passphrase.is_empty() {
        private_key.clone()
    } else {
        private_key
            .encrypt(&mut rng, passphrase.as_bytes())
            .map_err(|error| format!("加密私钥失败: {error}"))?
    };

    if let Err(error) = private_to_write.write_openssh_file(path, LineEnding::LF) {
        return Err(format!("写入私钥失败: {error}"));
    }
    if let Err(error) = private_key
        .public_key()
        .write_openssh_file(Path::new(&public_path))
    {
        let _ = fs::remove_file(path);
        return Err(format!("写入公钥失败: {error}"));
    }

    let id = uuid::Uuid::new_v4().to_string();
    let passphrase_ref = if request.save_passphrase && !passphrase.is_empty() {
        let reference = format!("key-{id}");
        match keyring::Entry::new(CREDENTIAL_SERVICE, &reference)
            .and_then(|entry| entry.set_password(&passphrase))
        {
            Ok(()) => Some(reference),
            Err(error) => {
                let _ = fs::remove_file(path);
                let _ = fs::remove_file(&public_path);
                return Err(format!("保存私钥口令失败: {error}"));
            }
        }
    } else {
        None
    };

    Ok(GeneratedKey {
        id,
        name: path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("SSH key")
            .to_string(),
        algorithm: request.algorithm,
        private_key_path: path.display().to_string(),
        public_key_path: public_path,
        fingerprint,
        passphrase_ref,
    })
}

pub(crate) fn read_public_key(path: &str) -> Result<String, String> {
    let metadata = fs::metadata(path).map_err(|error| format!("无法读取公钥: {error}"))?;
    if !metadata.is_file() || metadata.len() > 64 * 1024 {
        return Err("公钥文件无效或过大".to_string());
    }
    let value = fs::read_to_string(path).map_err(|error| format!("无法读取公钥: {error}"))?;
    let line = value.trim();
    let parsed: ssh_key::PublicKey = line
        .parse()
        .map_err(|_| "公钥不是有效的 OpenSSH 公钥".to_string())?;
    Ok(parsed
        .to_openssh()
        .map_err(|error| format!("公钥编码失败: {error}"))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_encrypted_ed25519_key_pair() {
        let root = std::env::temp_dir().join(format!("vpshell-key-{}", uuid::Uuid::new_v4()));
        let private_path = root.join("id_ed25519");
        let request = GenerateKeyRequest {
            algorithm: "ed25519".to_string(),
            path: private_path.display().to_string(),
            comment: "VPShell test".to_string(),
            passphrase: "test-passphrase-123".to_string(),
            save_passphrase: false,
        };

        let generated = generate_key(request).expect("key generation should succeed");
        assert_eq!(generated.algorithm, "ed25519");
        assert!(generated.fingerprint.starts_with("SHA256:"));
        assert!(generated.passphrase_ref.is_none());
        assert!(private_path.is_file());
        assert!(Path::new(&generated.public_key_path).is_file());
        assert!(read_public_key(&generated.public_key_path).is_ok());
        let private_text = fs::read_to_string(&private_path).expect("read private key");
        assert!(private_text.contains("BEGIN OPENSSH PRIVATE KEY"));
        assert!(!private_text.contains("test-passphrase-123"));

        fs::remove_dir_all(root).expect("remove key fixture directory");
    }
}
