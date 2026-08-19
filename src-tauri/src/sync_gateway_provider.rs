use std::{io::Read, time::Duration};

use reqwest::{
    StatusCode, Url,
    blocking::{Body, Client, RequestBuilder, Response},
    header::{CONTENT_LENGTH, CONTENT_TYPE, IF_NONE_MATCH},
    redirect::Policy,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    sync_provider::{
        ProviderCancellation, ProviderError, ProviderErrorCode, ProviderResult,
        validate_trusted_ca_pem,
    },
    sync_provider_ext::{
        ConditionalCreateResult, GatewayAuthenticator, GatewayObjectTransport,
        GatewayProviderConfig, ObjectTransport, TransportEntryKind, TransportObject,
    },
};

const PROTOCOL_VERSION: u16 = 1;
const MAX_JSON_BYTES: usize = 1024 * 1024;
const MAX_OBJECT_BYTES: usize = 24 * 1024 * 1024;
const MAX_SESSION_TOKEN_BYTES: usize = 4096;
const MIN_SESSION_SECONDS: u64 = 60;
const MAX_SESSION_SECONDS: u64 = 86_400;

#[derive(Clone)]
pub(crate) struct ReqwestGatewayAuthenticator {
    client: Client,
    endpoint: Url,
}

pub(crate) struct ReqwestGatewayObjectTransport {
    client: Client,
    endpoint: Url,
    session_token: Zeroizing<String>,
}

struct SecretRequestBody {
    bytes: Zeroizing<Vec<u8>>,
    offset: usize,
    cancellation: ProviderCancellation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginRequest<'a> {
    protocol_version: u16,
    vault_id: &'a str,
    device_id: &'a str,
    username: &'a str,
    password: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    totp: Option<&'a str>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LoginResponse {
    protocol_version: u16,
    session_token: String,
    expires_in_seconds: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ListResponse {
    protocol_version: u16,
    objects: Vec<ListObject>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ListObject {
    key: String,
    size: u64,
    etag: Option<String>,
}

impl ReqwestGatewayAuthenticator {
    pub(crate) fn connect(
        config: &GatewayProviderConfig,
        trusted_ca_pem: Option<&[u8]>,
    ) -> ProviderResult<Self> {
        config.validate()?;
        let endpoint = canonical_endpoint(&config.endpoint)?;
        let mut builder = Client::builder()
            .https_only(true)
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(config.timeout_seconds))
            .timeout(Duration::from_secs(config.timeout_seconds));
        if let Some(pem) = trusted_ca_pem {
            validate_trusted_ca_pem(pem)?;
            let certificate = reqwest::Certificate::from_pem(pem).map_err(|_| {
                provider_error(ProviderErrorCode::InvalidInput, "Gateway 自定义 CA 无效")
            })?;
            builder = builder.add_root_certificate(certificate);
        }
        let client = builder.build().map_err(|_| {
            provider_error(
                ProviderErrorCode::Unavailable,
                "无法创建 Gateway HTTPS 客户端",
            )
        })?;
        Ok(Self { client, endpoint })
    }
}

impl GatewayAuthenticator for ReqwestGatewayAuthenticator {
    type Session = ReqwestGatewayObjectTransport;

    fn authenticate(
        &self,
        config: &GatewayProviderConfig,
        username: &str,
        password: &str,
        totp: Option<&str>,
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<Self::Session> {
        cancellation.check()?;
        let request = LoginRequest {
            protocol_version: PROTOCOL_VERSION,
            vault_id: &config.vault_id,
            device_id: &config.device_id,
            username,
            password,
            totp,
        };
        let encoded = Zeroizing::new(serde_json::to_vec(&request).map_err(|_| {
            provider_error(ProviderErrorCode::InvalidInput, "Gateway 登录请求无效")
        })?);
        let encoded_length = encoded.len();
        let response = send(
            self.client
                .post(endpoint_url(&self.endpoint, "session")?)
                .header(CONTENT_TYPE, "application/json")
                .header(CONTENT_LENGTH, encoded_length)
                .body(Body::new(SecretRequestBody {
                    bytes: encoded,
                    offset: 0,
                    cancellation: cancellation.clone(),
                })),
            cancellation,
            "Gateway login",
        );
        let response = response?;
        if response.status() != StatusCode::OK {
            return Err(status_error(response.status(), "Gateway login"));
        }
        let bytes = Zeroizing::new(read_response(
            response,
            MAX_JSON_BYTES,
            cancellation,
            "Gateway login",
        )?);
        let session_token = parse_login_response(&bytes)?;
        Ok(ReqwestGatewayObjectTransport {
            client: self.client.clone(),
            endpoint: self.endpoint.clone(),
            session_token,
        })
    }
}

impl ReqwestGatewayObjectTransport {
    fn authorized(&self, request: RequestBuilder) -> RequestBuilder {
        request
            .bearer_auth(self.session_token.as_str())
            .header("x-vpshell-protocol", PROTOCOL_VERSION.to_string())
    }

    fn object_url(&self, key: &str) -> ProviderResult<Url> {
        let mut url = endpoint_url(&self.endpoint, "objects")?;
        url.path_segments_mut()
            .map_err(|_| {
                provider_error(ProviderErrorCode::InvalidInput, "Gateway endpoint 路径无效")
            })?
            .extend(key.split('/'));
        Ok(url)
    }
}

impl ObjectTransport for ReqwestGatewayObjectTransport {
    fn list_objects(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: usize,
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<Vec<TransportObject>> {
        let mut url = endpoint_url(&self.endpoint, "objects")?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("prefix", prefix);
            query.append_pair("limit", &limit.to_string());
            if let Some(cursor) = cursor {
                query.append_pair("after", cursor);
            }
        }
        let response = send(
            self.authorized(self.client.get(url)),
            cancellation,
            "Gateway list",
        )?;
        if response.status() != StatusCode::OK {
            return Err(status_error(response.status(), "Gateway list"));
        }
        let bytes = read_response(response, MAX_JSON_BYTES, cancellation, "Gateway list")?;
        parse_list_response(&bytes, limit)
    }

    fn get_object(
        &self,
        key: &str,
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<Vec<u8>> {
        let response = send(
            self.authorized(self.client.get(self.object_url(key)?)),
            cancellation,
            "Gateway get",
        )?;
        match response.status() {
            StatusCode::OK => {
                read_response(response, MAX_OBJECT_BYTES, cancellation, "Gateway get")
            }
            StatusCode::NOT_FOUND => Err(provider_error(
                ProviderErrorCode::NotFound,
                "Gateway 对象不存在",
            )),
            status => Err(status_error(status, "Gateway get")),
        }
    }

    fn create_object(
        &self,
        key: &str,
        bytes: &[u8],
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<ConditionalCreateResult> {
        cancellation.check()?;
        let response = send(
            self.authorized(
                self.client
                    .put(self.object_url(key)?)
                    .header(CONTENT_TYPE, "application/octet-stream")
                    .header(IF_NONE_MATCH, "*")
                    .body(bytes.to_vec()),
            ),
            cancellation,
            "Gateway conditional put",
        )?;
        match response.status() {
            StatusCode::CREATED => Ok(ConditionalCreateResult::Created),
            StatusCode::PRECONDITION_FAILED => Ok(ConditionalCreateResult::AlreadyExists),
            status => Err(status_error(status, "Gateway conditional put")),
        }
    }
}

impl GatewayObjectTransport for ReqwestGatewayObjectTransport {}

impl Read for SecretRequestBody {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.cancellation.check().is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "Gateway login cancelled",
            ));
        }
        let remaining = &self.bytes[self.offset..];
        let length = remaining.len().min(buffer.len());
        buffer[..length].copy_from_slice(&remaining[..length]);
        self.offset += length;
        Ok(length)
    }
}

fn parse_login_response(bytes: &[u8]) -> ProviderResult<Zeroizing<String>> {
    let response: LoginResponse = serde_json::from_slice(bytes)
        .map_err(|_| provider_error(ProviderErrorCode::Protocol, "Gateway 登录响应无效"))?;
    let session_token = Zeroizing::new(response.session_token);
    if response.protocol_version != PROTOCOL_VERSION
        || !(MIN_SESSION_SECONDS..=MAX_SESSION_SECONDS).contains(&response.expires_in_seconds)
        || session_token.is_empty()
        || session_token.len() > MAX_SESSION_TOKEN_BYTES
        || !session_token.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(provider_error(
            ProviderErrorCode::Protocol,
            "Gateway 登录响应字段无效",
        ));
    }
    Ok(session_token)
}

fn parse_list_response(bytes: &[u8], limit: usize) -> ProviderResult<Vec<TransportObject>> {
    let response: ListResponse = serde_json::from_slice(bytes)
        .map_err(|_| provider_error(ProviderErrorCode::Protocol, "Gateway list 响应无效"))?;
    if response.protocol_version != PROTOCOL_VERSION || response.objects.len() > limit {
        return Err(provider_error(
            ProviderErrorCode::Protocol,
            "Gateway list 响应版本或数量无效",
        ));
    }
    Ok(response
        .objects
        .into_iter()
        .map(|object| TransportObject {
            key: object.key,
            size: object.size,
            etag: object.etag,
            kind: TransportEntryKind::Regular,
        })
        .collect())
}

fn canonical_endpoint(endpoint: &str) -> ProviderResult<Url> {
    let mut endpoint = Url::parse(endpoint).map_err(|_| {
        provider_error(ProviderErrorCode::InvalidInput, "Gateway endpoint URL 无效")
    })?;
    if !endpoint.path().ends_with('/') {
        let path = format!("{}/", endpoint.path());
        endpoint.set_path(&path);
    }
    Ok(endpoint)
}

fn endpoint_url(endpoint: &Url, relative: &str) -> ProviderResult<Url> {
    endpoint
        .join(relative)
        .map_err(|_| provider_error(ProviderErrorCode::InvalidInput, "Gateway endpoint 路径无效"))
}

fn send(
    request: RequestBuilder,
    cancellation: &ProviderCancellation,
    operation: &str,
) -> ProviderResult<Response> {
    cancellation.check()?;
    let response = request.send().map_err(|_| {
        if cancellation.check().is_err() {
            provider_error(ProviderErrorCode::Cancelled, "Gateway 请求已取消")
        } else {
            provider_error(
                ProviderErrorCode::Unavailable,
                format!("{operation} HTTPS 请求失败"),
            )
        }
    })?;
    cancellation.check()?;
    Ok(response)
}

fn read_response(
    mut response: Response,
    maximum: usize,
    cancellation: &ProviderCancellation,
    operation: &str,
) -> ProviderResult<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(provider_error(
            ProviderErrorCode::LimitExceeded,
            format!("{operation} 响应超过大小上限"),
        ));
    }
    let mut output = Vec::new();
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        cancellation.check()?;
        let read = response.read(&mut chunk).map_err(|_| {
            provider_error(
                ProviderErrorCode::Unavailable,
                format!("无法读取 {operation} 响应"),
            )
        })?;
        if read == 0 {
            break;
        }
        if output.len().saturating_add(read) > maximum {
            return Err(provider_error(
                ProviderErrorCode::LimitExceeded,
                format!("{operation} 响应超过大小上限"),
            ));
        }
        output.extend_from_slice(&chunk[..read]);
    }
    Ok(output)
}

fn status_error(status: StatusCode, operation: &str) -> ProviderError {
    let code = match status {
        StatusCode::NOT_FOUND => ProviderErrorCode::NotFound,
        StatusCode::CONFLICT | StatusCode::PRECONDITION_FAILED => ProviderErrorCode::Conflict,
        StatusCode::UNAUTHORIZED
        | StatusCode::FORBIDDEN
        | StatusCode::TOO_MANY_REQUESTS
        | StatusCode::BAD_GATEWAY
        | StatusCode::SERVICE_UNAVAILABLE
        | StatusCode::GATEWAY_TIMEOUT => ProviderErrorCode::Unavailable,
        _ if status.is_server_error() => ProviderErrorCode::Unavailable,
        _ => ProviderErrorCode::Protocol,
    };
    provider_error(code, format!("{operation} 返回不支持的状态"))
}

fn provider_error(code: ProviderErrorCode, message: impl Into<String>) -> ProviderError {
    ProviderError::new(code, message)
}

#[cfg(test)]
mod tests {
    use std::{env, fs};

    use super::*;
    use crate::sync_provider::{PutObjectOutcome, SyncObjectProvider};
    use crate::sync_provider_ext::{GatewayLoginSecrets, GatewaySyncProvider};

    const VAULT_ID: &str = "11111111-1111-4111-8111-111111111111";
    const DEVICE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

    fn config(endpoint: String) -> GatewayProviderConfig {
        GatewayProviderConfig {
            endpoint,
            vault_id: VAULT_ID.to_string(),
            device_id: DEVICE_ID.to_string(),
            timeout_seconds: 10,
        }
    }

    #[test]
    fn endpoint_join_preserves_the_configured_api_base() {
        let endpoint = canonical_endpoint("https://gateway.example.test/api/v1").unwrap();
        assert_eq!(
            endpoint_url(&endpoint, "session").unwrap().as_str(),
            "https://gateway.example.test/api/v1/session"
        );
        let transport = ReqwestGatewayObjectTransport {
            client: Client::new(),
            endpoint,
            session_token: Zeroizing::new("fixture-token".to_string()),
        };
        assert_eq!(
            transport
                .object_url("vpshell/v1/object.oseg")
                .unwrap()
                .as_str(),
            "https://gateway.example.test/api/v1/objects/vpshell/v1/object.oseg"
        );
    }

    #[test]
    fn login_and_list_responses_reject_unknown_versions_fields_and_limits() {
        let valid_login =
            br#"{"protocolVersion":1,"sessionToken":"fixture-token","expiresInSeconds":300}"#;
        assert_eq!(
            parse_login_response(valid_login).unwrap().as_str(),
            "fixture-token"
        );
        for invalid in [
            &br#"{"protocolVersion":2,"sessionToken":"fixture-token","expiresInSeconds":300}"#[..],
            &br#"{"protocolVersion":1,"sessionToken":"line\nbreak","expiresInSeconds":300}"#[..],
            &br#"{"protocolVersion":1,"sessionToken":"fixture-token","expiresInSeconds":30}"#[..],
            &br#"{"protocolVersion":1,"sessionToken":"fixture-token","expiresInSeconds":300,"extra":true}"#[..],
        ] {
            assert!(parse_login_response(invalid).is_err());
        }

        let list =
            br#"{"protocolVersion":1,"objects":[{"key":"objects/a.oseg","size":1,"etag":"etag"}]}"#;
        assert_eq!(parse_list_response(list, 1).unwrap().len(), 1);
        assert!(parse_list_response(list, 0).is_err());
        assert!(parse_list_response(br#"{"protocolVersion":2,"objects":[]}"#, 1,).is_err());
        assert!(
            parse_list_response(br#"{"protocolVersion":1,"objects":[],"next":"forged"}"#, 1,)
                .is_err()
        );
    }

    #[test]
    fn real_gateway_provider_when_configured() {
        let Some(endpoint) = env::var("VPSHELL_GATEWAY_TEST_ENDPOINT").ok() else {
            return;
        };
        let ca_path = env::var("VPSHELL_GATEWAY_TEST_CA").expect("fixture CA");
        let ca = fs::read(ca_path).expect("fixture CA bytes");
        let config = config(endpoint);
        let authenticator =
            ReqwestGatewayAuthenticator::connect(&config, Some(&ca)).expect("authenticator");
        let cancellation = ProviderCancellation::default();
        let provider = GatewaySyncProvider::login(
            config,
            GatewayLoginSecrets::new(
                "fixture-user".to_string(),
                "fixture-password".to_string(),
                Some("123456".to_string()),
            )
            .expect("login secrets"),
            &authenticator,
            &cancellation,
        )
        .expect("gateway login");
        let first = b"gateway-provider-fixture";
        assert_eq!(
            provider
                .put("objects/fixture.oseg", first, &cancellation)
                .expect("create"),
            PutObjectOutcome::Created
        );
        assert_eq!(
            provider
                .put("objects/fixture.oseg", first, &cancellation)
                .expect("idempotent"),
            PutObjectOutcome::AlreadyPresent
        );
        assert_eq!(
            provider
                .get("objects/fixture.oseg", &cancellation)
                .expect("get"),
            first
        );
        let page = provider
            .list("objects/", None, 1, &cancellation)
            .expect("list");
        assert_eq!(page.objects.len(), 1);
        assert_eq!(page.objects[0].key, "objects/fixture.oseg");
        let conflict = provider
            .put("objects/fixture.oseg", b"different", &cancellation)
            .unwrap_err();
        assert_eq!(conflict.code, ProviderErrorCode::Conflict);
    }
}
