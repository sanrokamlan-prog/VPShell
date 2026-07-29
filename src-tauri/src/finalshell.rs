use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use base64::prelude::*;
use des::{
    Des,
    cipher::{Block, BlockCipherDecrypt, KeyInit},
};
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::CREDENTIAL_SERVICE;

const MAX_CONFIG_SIZE: u64 = 1024 * 1024;
const MAX_CONFIG_FILES: usize = 2000;

#[derive(Debug, Deserialize)]
struct FinalShellConfig {
    name: Option<String>,
    host: String,
    port: u16,
    user_name: String,
    password: Option<String>,
    proxy_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ImportedHost {
    id: String,
    name: String,
    group: String,
    host: String,
    port: u16,
    username: String,
    environment: String,
    tags: Vec<String>,
    credential_ref: Option<String>,
    source: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ImportResult {
    profiles: Vec<ImportedHost>,
    files_found: usize,
    credentials_imported: usize,
    credentials_failed: usize,
    files_skipped: usize,
}

#[derive(Clone, Copy)]
struct JavaRandom {
    seed: u64,
}

impl JavaRandom {
    const MULTIPLIER: u64 = 0x5DEECE66D;
    const ADDEND: u64 = 0xB;
    const MASK: u64 = (1_u64 << 48) - 1;

    fn new(seed: i64) -> Self {
        Self {
            seed: ((seed as u64) ^ Self::MULTIPLIER) & Self::MASK,
        }
    }

    fn next(&mut self, bits: u32) -> u32 {
        self.seed = self
            .seed
            .wrapping_mul(Self::MULTIPLIER)
            .wrapping_add(Self::ADDEND)
            & Self::MASK;
        (self.seed >> (48 - bits)) as u32
    }

    fn next_int(&mut self, bound: i32) -> i32 {
        assert!(bound > 0);
        if bound & (bound - 1) == 0 {
            return (((bound as i64) * (self.next(31) as i64)) >> 31) as i32;
        }

        loop {
            let bits = self.next(31) as i32;
            let value = bits % bound;
            if bits.wrapping_sub(value).wrapping_add(bound - 1) >= 0 {
                return value;
            }
        }
    }

    fn next_long(&mut self) -> i64 {
        let high = self.next(32) as i32 as i64;
        let low = self.next(32) as i32 as i64;
        high.wrapping_shl(32).wrapping_add(low)
    }
}

fn signed_byte(value: u8) -> i64 {
    value as i8 as i64
}

fn derive_finalshell_key(head: &[u8; 8]) -> Result<[u8; 16], String> {
    let mut seeded = JavaRandom::new(signed_byte(head[5]));
    let divisor = seeded.next_int(127);
    if divisor == 0 {
        return Err("FinalShell 密钥头无效".to_string());
    }

    let seed = 3_680_984_568_597_093_857_i64 / divisor as i64;
    let mut random = JavaRandom::new(seed);
    let advance = signed_byte(head[0]).max(0) as usize;
    for _ in 0..advance {
        random.next_long();
    }

    let mut random2 = JavaRandom::new(random.next_long());
    let values = [
        signed_byte(head[4]),
        random2.next_long(),
        signed_byte(head[7]),
        signed_byte(head[3]),
        random2.next_long(),
        signed_byte(head[1]),
        random.next_long(),
        signed_byte(head[2]),
    ];

    let mut material = [0_u8; 64];
    for (index, value) in values.iter().enumerate() {
        material[index * 8..(index + 1) * 8].copy_from_slice(&value.to_be_bytes());
    }

    let digest = Md5::digest(material);
    let mut key = [0_u8; 16];
    key.copy_from_slice(&digest);
    Ok(key)
}

fn decrypt_finalshell_password(encoded: &str) -> Result<Zeroizing<String>, String> {
    let decoded = BASE64_STANDARD
        .decode(encoded)
        .map_err(|_| "FinalShell 密码不是有效 Base64".to_string())?;
    if decoded.len() < 16 || (decoded.len() - 8) % 8 != 0 {
        return Err("FinalShell 密码长度无效".to_string());
    }

    let head: [u8; 8] = decoded[..8]
        .try_into()
        .map_err(|_| "FinalShell 密钥头无效".to_string())?;
    let key = derive_finalshell_key(&head)?;
    let cipher = Des::new_from_slice(&key[..8]).map_err(|_| "DES 密钥无效".to_string())?;
    let mut plaintext = decoded[8..].to_vec();

    for chunk in plaintext.chunks_exact_mut(8) {
        let mut block = Block::<Des>::default();
        block.copy_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }

    let padding = *plaintext
        .last()
        .ok_or_else(|| "FinalShell 密码内容为空".to_string())? as usize;
    if padding == 0
        || padding > 8
        || plaintext.len() < padding
        || !plaintext[plaintext.len() - padding..]
            .iter()
            .all(|value| *value as usize == padding)
    {
        return Err("FinalShell 密码填充无效".to_string());
    }
    plaintext.truncate(plaintext.len() - padding);

    let password =
        String::from_utf8(plaintext).map_err(|_| "FinalShell 密码不是 UTF-8".to_string())?;
    if password.contains(['\r', '\n', '\0']) {
        return Err("FinalShell 密码包含不支持的控制字符".to_string());
    }
    Ok(Zeroizing::new(password))
}

fn collect_config_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let metadata = fs::metadata(root).map_err(|error| format!("无法读取导入目录: {error}"))?;
    if !metadata.is_dir() {
        return Err("FinalShell 导入路径必须是文件夹".to_string());
    }

    let mut files = Vec::new();
    let mut directories = vec![root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(&directory).map_err(|error| format!("无法读取目录: {error}"))?
        {
            let entry = entry.map_err(|error| format!("无法读取目录项: {error}"))?;
            let file_type = entry
                .file_type()
                .map_err(|error| format!("无法识别目录项: {error}"))?;
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                directories.push(entry.path());
                continue;
            }
            let file_name = entry.file_name();
            if file_type.is_file()
                && file_name
                    .to_string_lossy()
                    .ends_with("_connect_config.json")
            {
                files.push(entry.path());
                if files.len() > MAX_CONFIG_FILES {
                    return Err("FinalShell 配置文件超过 2000 个，请缩小导入目录".to_string());
                }
            }
        }
    }
    files.sort();
    Ok(files)
}

pub(crate) fn import_directory(
    path: &str,
    include_passwords: bool,
) -> Result<ImportResult, String> {
    let files = collect_config_files(Path::new(path))?;
    if files.is_empty() {
        return Err("目录中没有找到 FinalShell 连接配置".to_string());
    }

    let mut profiles = Vec::new();
    let mut credentials_imported = 0;
    let mut credentials_failed = 0;
    let mut files_skipped = 0;
    let mut seen = HashSet::new();

    for file in &files {
        let metadata = match fs::metadata(file) {
            Ok(metadata) if metadata.len() <= MAX_CONFIG_SIZE => metadata,
            _ => {
                files_skipped += 1;
                continue;
            }
        };
        if !metadata.is_file() {
            files_skipped += 1;
            continue;
        }

        let bytes = match fs::read(file) {
            Ok(bytes) => bytes,
            Err(_) => {
                files_skipped += 1;
                continue;
            }
        };
        let config: FinalShellConfig = match serde_json::from_slice(&bytes) {
            Ok(config) => config,
            Err(_) => {
                files_skipped += 1;
                continue;
            }
        };

        if config.host.trim().is_empty()
            || config.host.starts_with('-')
            || config.host.chars().any(char::is_whitespace)
            || config.user_name.trim().is_empty()
            || config.user_name.contains('@')
            || config.user_name.chars().any(char::is_whitespace)
        {
            files_skipped += 1;
            continue;
        }

        let dedupe_key = format!("{}\0{}\0{}", config.host, config.port, config.user_name);
        if !seen.insert(dedupe_key) {
            files_skipped += 1;
            continue;
        }

        let id = uuid::Uuid::new_v4().to_string();
        let credential_ref = if include_passwords {
            match config.password.as_deref().filter(|value| !value.is_empty()) {
                Some(encoded) => match decrypt_finalshell_password(encoded) {
                    Ok(password) => {
                        let reference = format!("ssh-{id}");
                        match keyring::Entry::new(CREDENTIAL_SERVICE, &reference)
                            .and_then(|entry| entry.set_password(&password))
                        {
                            Ok(()) => {
                                credentials_imported += 1;
                                Some(reference)
                            }
                            Err(_) => {
                                credentials_failed += 1;
                                None
                            }
                        }
                    }
                    Err(_) => {
                        credentials_failed += 1;
                        None
                    }
                },
                None => None,
            }
        } else {
            None
        };

        let fallback_name = file
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("FinalShell 主机")
            .trim_end_matches("_connect_config.json")
            .to_string();

        profiles.push(ImportedHost {
            id,
            name: config
                .name
                .filter(|value| !value.trim().is_empty())
                .unwrap_or(fallback_name),
            group: "FinalShell 导入".to_string(),
            host: config.host,
            port: config.port,
            username: config.user_name,
            environment: "development".to_string(),
            tags: if config.proxy_id.as_deref().is_some_and(|value| value != "0") {
                vec!["原配置含代理".to_string()]
            } else {
                Vec::new()
            },
            credential_ref,
            source: "finalshell".to_string(),
        });
    }

    Ok(ImportResult {
        profiles,
        files_found: files.len(),
        credentials_imported,
        credentials_failed,
        files_skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_public_finalshell_fixture() {
        let password = decrypt_finalshell_password("UU8hWV51DmVNgmX/pUd0LlaEo53VTa6s")
            .expect("public fixture should decode");
        assert_eq!(&*password, "beac3d85988e");
    }

    #[test]
    fn rejects_invalid_ciphertext() {
        assert!(decrypt_finalshell_password("not-base64").is_err());
    }

    #[test]
    fn imports_and_deduplicates_connection_files_without_credentials() {
        let root =
            std::env::temp_dir().join(format!("vpshell-finalshell-{}", uuid::Uuid::new_v4()));
        let nested = root.join("nested");
        fs::create_dir_all(&nested).expect("create fixture directory");
        let fixture = r#"{
            "name": "Example host",
            "host": "192.0.2.10",
            "port": 2222,
            "user_name": "root",
            "password": "",
            "proxy_id": "0"
        }"#;
        fs::write(root.join("one_connect_config.json"), fixture).expect("write fixture");
        fs::write(nested.join("duplicate_connect_config.json"), fixture).expect("write duplicate");

        let result = import_directory(root.to_str().expect("utf-8 temp path"), false)
            .expect("fixture should import");
        assert_eq!(result.files_found, 2);
        assert_eq!(result.profiles.len(), 1);
        assert_eq!(result.files_skipped, 1);
        assert_eq!(result.credentials_imported, 0);
        assert_eq!(result.profiles[0].host, "192.0.2.10");
        assert!(result.profiles[0].credential_ref.is_none());

        fs::remove_dir_all(root).expect("remove fixture directory");
    }
}
