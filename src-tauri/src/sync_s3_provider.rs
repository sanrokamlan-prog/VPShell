use std::{
    collections::BTreeMap,
    io::Read,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use hmac::{Hmac, Mac};
use quick_xml::{Reader, events::Event};
use reqwest::{
    Certificate, Method, StatusCode, Url,
    blocking::{Body, Client, RequestBuilder, Response},
    header::{CONTENT_LENGTH, HeaderValue, IF_NONE_MATCH},
    redirect::Policy,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    sync_provider::{
        ProviderCancellation, ProviderError, ProviderErrorCode, ProviderResult,
        validate_object_bytes, validate_trusted_ca_pem,
    },
    sync_provider_credentials::S3Credentials,
    sync_provider_ext::{
        ConditionalCreateResult, ObjectTransport, S3CompatibleTransport, S3ProviderConfig,
        TransportEntryKind, TransportObject,
    },
};

const MAX_OBJECT_BYTES: usize = 24 * 1024 * 1024;
const MAX_LIST_XML_BYTES: usize = 4 * 1024 * 1024;
const MAX_LIST_OBJECTS: usize = 10_000;
const MAX_CONTINUATION_TOKEN_BYTES: usize = 2_048;
const MAX_RESPONSE_CHUNK: usize = 64 * 1024;

type HmacSha256 = Hmac<Sha256>;

pub(crate) struct ReqwestS3ObjectTransport {
    config: S3ProviderConfig,
    endpoint: Url,
    client: Client,
    credentials: S3Credentials,
}

impl ReqwestS3ObjectTransport {
    pub(crate) fn connect(
        config: S3ProviderConfig,
        credentials: S3Credentials,
        trusted_ca_pem: Option<&[u8]>,
    ) -> ProviderResult<Self> {
        config.validate()?;
        let endpoint = Url::parse(&config.endpoint).map_err(|_| {
            provider_error(ProviderErrorCode::InvalidInput, "S3 endpoint URL 无效")
        })?;
        if endpoint.path() != "/" {
            return Err(provider_error(
                ProviderErrorCode::InvalidInput,
                "S3 endpoint 不能包含基础路径",
            ));
        }
        let timeout = Duration::from_secs(config.timeout_seconds);
        let mut builder = Client::builder()
            .https_only(true)
            .connect_timeout(timeout.min(Duration::from_secs(10)))
            .timeout(timeout)
            .redirect(Policy::none());
        if let Some(pem) = trusted_ca_pem {
            validate_trusted_ca_pem(pem)?;
            let certificate = Certificate::from_pem(pem).map_err(|_| {
                provider_error(ProviderErrorCode::InvalidInput, "S3 自定义 CA 无效")
            })?;
            builder = builder.add_root_certificate(certificate);
        }
        let client = builder.build().map_err(|_| {
            provider_error(ProviderErrorCode::Unavailable, "无法创建 S3 HTTPS 客户端")
        })?;
        Ok(Self {
            config,
            endpoint,
            client,
            credentials,
        })
    }

    fn physical_key(&self, key: &str) -> String {
        if self.config.prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}/{}", self.config.prefix, key)
        }
    }

    fn logical_key(&self, physical: &str) -> ProviderResult<String> {
        if self.config.prefix.is_empty() {
            return Ok(physical.to_string());
        }
        physical
            .strip_prefix(&format!("{}/", self.config.prefix))
            .map(str::to_string)
            .ok_or_else(|| {
                provider_error(
                    ProviderErrorCode::Protocol,
                    "S3 list 返回前缀作用域之外的对象",
                )
            })
    }

    fn object_url(&self, key: &str) -> ProviderResult<Url> {
        let mut url = self.endpoint.clone();
        let physical = self.physical_key(key);
        if self.config.path_style {
            url.set_path(&format!("/{}/{}", self.config.bucket, physical));
        } else {
            let endpoint_host = url.host_str().map(str::to_string).ok_or_else(|| {
                provider_error(ProviderErrorCode::InvalidInput, "S3 endpoint 缺少 host")
            })?;
            url.set_host(Some(&format!("{}.{}", self.config.bucket, endpoint_host)))
                .map_err(|_| {
                    provider_error(ProviderErrorCode::InvalidInput, "S3 bucket host 无效")
                })?;
            url.set_path(&format!("/{physical}"));
        }
        Ok(url)
    }

    fn bucket_url(&self) -> ProviderResult<Url> {
        let mut url = self.endpoint.clone();
        if self.config.path_style {
            url.set_path(&format!("/{}/", self.config.bucket));
        } else {
            let endpoint_host = url.host_str().map(str::to_string).ok_or_else(|| {
                provider_error(ProviderErrorCode::InvalidInput, "S3 endpoint 缺少 host")
            })?;
            url.set_host(Some(&format!("{}.{}", self.config.bucket, endpoint_host)))
                .map_err(|_| {
                    provider_error(ProviderErrorCode::InvalidInput, "S3 bucket host 无效")
                })?;
            url.set_path("/");
        }
        Ok(url)
    }

    fn signed_request(
        &self,
        method: Method,
        mut url: Url,
        query: &BTreeMap<String, String>,
        payload_hash: &str,
        now: SystemTime,
    ) -> ProviderResult<RequestBuilder> {
        let canonical_query = canonical_query(query);
        url.set_query((!canonical_query.is_empty()).then_some(&canonical_query));
        let signature = sign_v4(
            method.as_str(),
            &url,
            &canonical_query,
            payload_hash,
            &self.config.region,
            &self.credentials,
            now,
        )?;
        let mut request = self
            .client
            .request(method, url)
            .header("x-amz-content-sha256", payload_hash)
            .header("x-amz-date", signature.amz_date)
            .header("authorization", signature.authorization);
        if let Some(token) = self.credentials.session_token() {
            request = request.header("x-amz-security-token", token);
        }
        Ok(request)
    }

    fn execute(
        &self,
        request: RequestBuilder,
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<Response> {
        request.send().map_err(|_| {
            if cancellation.check().is_err() {
                provider_error(ProviderErrorCode::Cancelled, "S3 请求已取消")
            } else {
                provider_error(ProviderErrorCode::Unavailable, "S3 HTTPS 请求失败")
            }
        })
    }

    fn read_response(
        &self,
        response: Response,
        maximum: usize,
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<Vec<u8>> {
        if response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length > maximum as u64)
        {
            return Err(provider_error(
                ProviderErrorCode::LimitExceeded,
                "S3 响应超过大小上限",
            ));
        }
        read_bounded(response, maximum, cancellation)
    }

    fn list_page(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        continuation: Option<&str>,
        limit: usize,
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<S3ListPage> {
        cancellation.check()?;
        let scoped_prefix = if self.config.prefix.is_empty() {
            prefix.to_string()
        } else if prefix.is_empty() {
            format!("{}/", self.config.prefix)
        } else {
            format!("{}/{}", self.config.prefix, prefix)
        };
        let mut query = BTreeMap::from([
            ("list-type".to_string(), "2".to_string()),
            ("max-keys".to_string(), limit.min(1_000).to_string()),
            ("prefix".to_string(), scoped_prefix),
        ]);
        if continuation.is_none() {
            if let Some(cursor) = start_after {
                query.insert("start-after".to_string(), self.physical_key(cursor));
            }
        }
        if let Some(token) = continuation {
            if token.is_empty()
                || token.len() > MAX_CONTINUATION_TOKEN_BYTES
                || token.chars().any(char::is_control)
            {
                return Err(provider_error(
                    ProviderErrorCode::Protocol,
                    "S3 continuation token 无效",
                ));
            }
            query.insert("continuation-token".to_string(), token.to_string());
        }
        let request = self.signed_request(
            Method::GET,
            self.bucket_url()?,
            &query,
            &sha256_hex(b""),
            SystemTime::now(),
        )?;
        let response = self.execute(request, cancellation)?;
        if response.status() != StatusCode::OK {
            return Err(status_error(response.status(), "S3 list"));
        }
        let encoded = self.read_response(response, MAX_LIST_XML_BYTES, cancellation)?;
        parse_list_objects_v2(&encoded)
    }
}

impl ObjectTransport for ReqwestS3ObjectTransport {
    fn list_objects(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: usize,
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<Vec<TransportObject>> {
        let mut output = Vec::new();
        let mut continuation = None;
        loop {
            cancellation.check()?;
            let remaining = limit.saturating_sub(output.len()).max(1);
            let page = self.list_page(
                prefix,
                cursor,
                continuation.as_deref(),
                remaining,
                cancellation,
            )?;
            let page_had_objects = !page.objects.is_empty();
            for object in page.objects {
                let key = self.logical_key(&object.key)?;
                output.push(TransportObject {
                    key,
                    size: object.size,
                    etag: object.etag,
                    kind: TransportEntryKind::Regular,
                });
                if output.len() > MAX_LIST_OBJECTS {
                    return Err(provider_error(
                        ProviderErrorCode::LimitExceeded,
                        "S3 list 超过 10000 项",
                    ));
                }
                if output.len() >= limit {
                    return Ok(output);
                }
            }
            if !page.truncated {
                return Ok(output);
            }
            if !page_had_objects {
                return Err(provider_error(
                    ProviderErrorCode::Protocol,
                    "S3 截断列表未返回可推进的对象",
                ));
            }
            let next = page.next_continuation_token.ok_or_else(|| {
                provider_error(
                    ProviderErrorCode::Protocol,
                    "S3 截断列表缺少 continuation token",
                )
            })?;
            if continuation.as_ref() == Some(&next) {
                return Err(provider_error(
                    ProviderErrorCode::Protocol,
                    "S3 continuation token 未前进",
                ));
            }
            continuation = Some(next);
        }
    }

    fn get_object(
        &self,
        key: &str,
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<Vec<u8>> {
        cancellation.check()?;
        let request = self.signed_request(
            Method::GET,
            self.object_url(key)?,
            &BTreeMap::new(),
            &sha256_hex(b""),
            SystemTime::now(),
        )?;
        let response = self.execute(request, cancellation)?;
        match response.status() {
            StatusCode::OK => self.read_response(response, MAX_OBJECT_BYTES, cancellation),
            StatusCode::NOT_FOUND => Err(provider_error(
                ProviderErrorCode::NotFound,
                "S3 对象不存在",
            )),
            status => Err(status_error(status, "S3 get")),
        }
    }

    fn create_object(
        &self,
        key: &str,
        bytes: &[u8],
        cancellation: &ProviderCancellation,
    ) -> ProviderResult<ConditionalCreateResult> {
        validate_object_bytes(bytes)?;
        cancellation.check()?;
        let request = self
            .signed_request(
                Method::PUT,
                self.object_url(key)?,
                &BTreeMap::new(),
                &sha256_hex(bytes),
                SystemTime::now(),
            )?
            .header(IF_NONE_MATCH, HeaderValue::from_static("*"))
            .header(CONTENT_LENGTH, bytes.len())
            .body(Body::new(CancellableUpload::new(
                bytes.to_vec(),
                cancellation.clone(),
            )));
        let response = self.execute(request, cancellation)?;
        match response.status() {
            StatusCode::OK | StatusCode::CREATED | StatusCode::NO_CONTENT => {
                Ok(ConditionalCreateResult::Created)
            }
            StatusCode::PRECONDITION_FAILED => {
                Ok(ConditionalCreateResult::AlreadyExists)
            }
            StatusCode::CONFLICT => Err(provider_error(
                ProviderErrorCode::Unavailable,
                "S3 条件写入发生可重试竞态",
            )),
            status => Err(status_error(status, "S3 conditional put")),
        }
    }
}

impl S3CompatibleTransport for ReqwestS3ObjectTransport {}

struct V4Signature {
    amz_date: String,
    authorization: String,
}

fn sign_v4(
    method: &str,
    url: &Url,
    canonical_query: &str,
    payload_hash: &str,
    region: &str,
    credentials: &S3Credentials,
    now: SystemTime,
) -> ProviderResult<V4Signature> {
    let (date, amz_date) = aws_timestamp(now)?;
    let host = canonical_host(url)?;
    let mut canonical_headers = format!(
        "host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
    );
    let mut signed_headers = "host;x-amz-content-sha256;x-amz-date".to_string();
    if let Some(token) = credentials.session_token() {
        canonical_headers.push_str(&format!("x-amz-security-token:{}\n", trim_header(token)?));
        signed_headers.push_str(";x-amz-security-token");
    }
    let canonical_request = format!(
        "{method}\n{}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
        canonical_uri(url.path())
    );
    let scope = format!("{date}/{region}/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let secret = Zeroizing::new(format!("AWS4{}", credentials.secret_access_key()));
    let date_key = Zeroizing::new(hmac_sha256(secret.as_bytes(), date.as_bytes())?);
    let region_key = Zeroizing::new(hmac_sha256(date_key.as_slice(), region.as_bytes())?);
    let service_key = Zeroizing::new(hmac_sha256(region_key.as_slice(), b"s3")?);
    let signing_key = Zeroizing::new(hmac_sha256(service_key.as_slice(), b"aws4_request")?);
    let signature = hex(&hmac_sha256(
        signing_key.as_slice(),
        string_to_sign.as_bytes(),
    )?);
    Ok(V4Signature {
        amz_date,
        authorization: format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            credentials.access_key_id()
        ),
    })
}

fn canonical_host(url: &Url) -> ProviderResult<String> {
    let host = url.host_str().ok_or_else(|| {
        provider_error(ProviderErrorCode::InvalidInput, "S3 请求 URL 缺少 host")
    })?;
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let default_port = match url.scheme() {
        "https" => 443,
        "http" => 80,
        _ => 0,
    };
    Ok(match url.port() {
        Some(port) if port != default_port => format!("{host}:{port}"),
        _ => host,
    })
}

fn trim_header(value: &str) -> ProviderResult<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
        return Err(provider_error(
            ProviderErrorCode::InvalidInput,
            "S3 session token 无效",
        ));
    }
    Ok(trimmed)
}

fn canonical_uri(path: &str) -> String {
    if path.is_empty() {
        "/".to_string()
    } else {
        path.split('/')
            .map(|segment| aws_uri_encode(segment.as_bytes()))
            .collect::<Vec<_>>()
            .join("/")
    }
}

fn canonical_query(values: &BTreeMap<String, String>) -> String {
    values
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                aws_uri_encode(key.as_bytes()),
                aws_uri_encode(value.as_bytes())
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn aws_uri_encode(bytes: &[u8]) -> String {
    let mut output = String::new();
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.' | b'~') {
            output.push(char::from(*byte));
        } else {
            output.push('%');
            output.push(char::from(b"0123456789ABCDEF"[(byte >> 4) as usize]));
            output.push(char::from(b"0123456789ABCDEF"[(byte & 0x0f) as usize]));
        }
    }
    output
}

fn aws_timestamp(now: SystemTime) -> ProviderResult<(String, String)> {
    let seconds = now.duration_since(UNIX_EPOCH).map_err(|_| {
        provider_error(ProviderErrorCode::Unavailable, "系统时间早于 Unix epoch")
    })?;
    let total = seconds.as_secs();
    let days = (total / 86_400) as i64;
    let seconds_of_day = total % 86_400;
    let (year, month, day) = civil_from_days(days);
    if !(1970..=9999).contains(&year) {
        return Err(provider_error(
            ProviderErrorCode::Unavailable,
            "系统时间超出 S3 签名范围",
        ));
    }
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    let date = format!("{year:04}{month:02}{day:02}");
    Ok((
        date.clone(),
        format!("{date}T{hour:02}{minute:02}{second:02}Z"),
    ))
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096)
            / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += if month <= 2 { 1 } else { 0 };
    (year, month as u32, day as u32)
}

fn hmac_sha256(key: &[u8], bytes: &[u8]) -> ProviderResult<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| {
        provider_error(ProviderErrorCode::InvalidInput, "S3 签名密钥无效")
    })?;
    mac.update(bytes);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[(byte >> 4) as usize]));
        output.push(char::from(DIGITS[(byte & 0x0f) as usize]));
    }
    output
}

fn read_bounded(
    mut reader: impl Read,
    maximum: usize,
    cancellation: &ProviderCancellation,
) -> ProviderResult<Vec<u8>> {
    let mut output = Vec::new();
    let mut chunk = [0u8; MAX_RESPONSE_CHUNK];
    loop {
        cancellation.check()?;
        let read = reader.read(&mut chunk).map_err(|_| {
            provider_error(ProviderErrorCode::Unavailable, "无法读取 S3 响应")
        })?;
        if read == 0 {
            break;
        }
        if output.len().saturating_add(read) > maximum {
            return Err(provider_error(
                ProviderErrorCode::LimitExceeded,
                "S3 响应超过大小上限",
            ));
        }
        output.extend_from_slice(&chunk[..read]);
    }
    Ok(output)
}

struct CancellableUpload {
    bytes: Vec<u8>,
    offset: usize,
    cancellation: ProviderCancellation,
}

impl CancellableUpload {
    fn new(bytes: Vec<u8>, cancellation: ProviderCancellation) -> Self {
        Self {
            bytes,
            offset: 0,
            cancellation,
        }
    }
}

impl Read for CancellableUpload {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.cancellation.check().is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "S3 upload cancelled",
            ));
        }
        let remaining = &self.bytes[self.offset..];
        let count = remaining.len().min(buffer.len());
        buffer[..count].copy_from_slice(&remaining[..count]);
        self.offset += count;
        Ok(count)
    }
}

#[derive(Default)]
struct S3ListPage {
    objects: Vec<S3ListObject>,
    truncated: bool,
    next_continuation_token: Option<String>,
}

#[derive(Default)]
struct S3ListObject {
    key: String,
    size: u64,
    etag: Option<String>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ListField {
    None,
    Key,
    Size,
    Etag,
    IsTruncated,
    NextContinuationToken,
}

fn parse_list_objects_v2(xml: &[u8]) -> ProviderResult<S3ListPage> {
    if xml.is_empty() || xml.len() > MAX_LIST_XML_BYTES {
        return Err(provider_error(
            ProviderErrorCode::LimitExceeded,
            "S3 list XML 为空或超过上限",
        ));
    }
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);
    let mut buffer = Vec::new();
    let mut depth = 0usize;
    let mut page = S3ListPage::default();
    let mut current = None;
    let mut field = ListField::None;
    let mut saw_root = false;
    let mut closed_root = false;
    let mut saw_is_truncated = false;
    loop {
        match reader.read_event_into(&mut buffer).map_err(|_| {
            provider_error(ProviderErrorCode::Protocol, "S3 list XML 无效")
        })? {
            Event::Start(event) => {
                depth += 1;
                if depth > 16 {
                    return Err(provider_error(
                        ProviderErrorCode::LimitExceeded,
                        "S3 list XML 嵌套超过限制",
                    ));
                }
                if depth == 1 {
                    if saw_root || event.local_name().as_ref() != b"ListBucketResult" {
                        return Err(provider_error(
                            ProviderErrorCode::Protocol,
                            "S3 list XML 根元素无效",
                        ));
                    }
                    saw_root = true;
                }
                match event.local_name().as_ref() {
                    b"Contents" => current = Some(S3ListObject::default()),
                    b"Key" => field = ListField::Key,
                    b"Size" => field = ListField::Size,
                    b"ETag" => field = ListField::Etag,
                    b"IsTruncated" => field = ListField::IsTruncated,
                    b"NextContinuationToken" => field = ListField::NextContinuationToken,
                    _ => {}
                }
            }
            Event::Text(event) => {
                let value = event.decode().map_err(|_| {
                    provider_error(ProviderErrorCode::Protocol, "S3 list XML 文本编码无效")
                })?;
                if value.len() > MAX_CONTINUATION_TOKEN_BYTES {
                    return Err(provider_error(
                        ProviderErrorCode::LimitExceeded,
                        "S3 list XML 字段超过限制",
                    ));
                }
                match field {
                    ListField::Key => {
                        if let Some(object) = &mut current {
                            object.key = value.into_owned();
                        }
                    }
                    ListField::Size => {
                        if let Some(object) = &mut current {
                            object.size = value.parse().map_err(|_| {
                                provider_error(
                                    ProviderErrorCode::Protocol,
                                    "S3 对象长度无效",
                                )
                            })?;
                        }
                    }
                    ListField::Etag => {
                        if let Some(object) = &mut current {
                            object.etag = Some(value.trim_matches('"').to_string());
                        }
                    }
                    ListField::IsTruncated => {
                        page.truncated = match value.as_ref() {
                            "true" => true,
                            "false" => false,
                            _ => {
                                return Err(provider_error(
                                    ProviderErrorCode::Protocol,
                                    "S3 IsTruncated 无效",
                                ));
                            }
                        };
                        saw_is_truncated = true;
                    }
                    ListField::NextContinuationToken => {
                        page.next_continuation_token = Some(value.into_owned());
                    }
                    ListField::None => {}
                }
            }
            Event::End(event) => {
                if depth == 0 {
                    return Err(provider_error(
                        ProviderErrorCode::Protocol,
                        "S3 list XML 元素层级无效",
                    ));
                }
                match event.local_name().as_ref() {
                    b"Contents" => {
                        let object = current.take().ok_or_else(|| {
                            provider_error(ProviderErrorCode::Protocol, "S3 Contents 状态无效")
                        })?;
                        if object.key.is_empty() || object.size == 0 {
                            return Err(provider_error(
                                ProviderErrorCode::Protocol,
                                "S3 list 对象缺少 key 或有效长度",
                            ));
                        }
                        page.objects.push(object);
                        if page.objects.len() > MAX_LIST_OBJECTS {
                            return Err(provider_error(
                                ProviderErrorCode::LimitExceeded,
                                "S3 list 超过 10000 项",
                            ));
                        }
                    }
                    b"Key" | b"Size" | b"ETag" | b"IsTruncated"
                    | b"NextContinuationToken" => field = ListField::None,
                    _ => {}
                }
                if depth == 1 {
                    closed_root = true;
                }
                depth -= 1;
            }
            Event::DocType(_) => {
                return Err(provider_error(
                    ProviderErrorCode::Protocol,
                    "S3 list XML 不允许 DTD",
                ));
            }
            Event::Eof => break,
            _ => {}
        }
        buffer.clear();
    }
    if !saw_root || !closed_root || !saw_is_truncated || depth != 0 || current.is_some() {
        return Err(provider_error(
            ProviderErrorCode::Protocol,
            "S3 list XML 不完整",
        ));
    }
    if page.truncated && page.next_continuation_token.as_deref().is_none_or(str::is_empty) {
        return Err(provider_error(
            ProviderErrorCode::Protocol,
            "S3 截断列表缺少 continuation token",
        ));
    }
    Ok(page)
}

fn status_error(status: StatusCode, operation: &str) -> ProviderError {
    let code = match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => ProviderErrorCode::Unavailable,
        StatusCode::NOT_FOUND => ProviderErrorCode::NotFound,
        StatusCode::CONFLICT | StatusCode::PRECONDITION_FAILED => ProviderErrorCode::Conflict,
        StatusCode::TOO_MANY_REQUESTS
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

    use crate::{
        sync_provider::{ProviderCancellation, ProviderErrorCode, SyncObjectProvider},
        sync_provider_credentials::S3Credentials,
        sync_provider_ext::{S3ProviderConfig, S3SyncProvider},
    };

    use super::*;

    fn credentials() -> S3Credentials {
        S3Credentials::new(
            "AKIDEXAMPLE".to_string(),
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
            None,
        )
        .unwrap()
    }

    #[test]
    fn timestamp_and_sigv4_are_deterministic_and_secret_free() {
        let now = UNIX_EPOCH + Duration::from_secs(1_443_442_096);
        assert_eq!(
            aws_timestamp(now).unwrap(),
            ("20150928".to_string(), "20150928T120816Z".to_string())
        );
        let url = Url::parse("https://examplebucket.s3.amazonaws.com/test.txt").unwrap();
        let signed = sign_v4(
            "GET",
            &url,
            "",
            &sha256_hex(b""),
            "us-east-1",
            &credentials(),
            now,
        )
        .unwrap();
        assert!(
            signed
                .authorization
                .starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/")
        );
        assert!(
            signed
                .authorization
                .contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date")
        );
        assert!(!signed.authorization.contains("wJalr"));
        let signature = signed.authorization.rsplit('=').next().unwrap();
        assert_eq!(
            signature,
            "3bd634ec6b341f71c50d67480af8fc3d29feb1c90569c64d9f3e4eeffbd17045"
        );
    }

    #[test]
    fn list_xml_is_bounded_and_requires_forward_token() {
        let page = parse_list_objects_v2(
            br#"<?xml version="1.0" encoding="UTF-8"?>
              <ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                <IsTruncated>true</IsTruncated>
                <Contents><Key>scope/objects/a.oseg</Key><ETag>"abc"</ETag><Size>5</Size></Contents>
                <NextContinuationToken>next-1</NextContinuationToken>
              </ListBucketResult>"#,
        )
        .unwrap();
        assert!(page.truncated);
        assert_eq!(page.next_continuation_token.as_deref(), Some("next-1"));
        assert_eq!(page.objects[0].key, "scope/objects/a.oseg");
        assert_eq!(page.objects[0].etag.as_deref(), Some("abc"));
        assert!(
            parse_list_objects_v2(
                b"<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>"
            )
            .is_err()
        );
        assert!(parse_list_objects_v2(b"<!DOCTYPE x><ListBucketResult />").is_err());
        assert!(parse_list_objects_v2(b"<ListBucketResult><IsTruncated>false").is_err());
        assert!(
            parse_list_objects_v2(b"<Unexpected><IsTruncated>false</IsTruncated></Unexpected>")
                .is_err()
        );
    }

    #[test]
    fn object_urls_cover_path_and_virtual_hosted_styles() {
        let config = |path_style| S3ProviderConfig {
            endpoint: "https://s3.example.test/".to_string(),
            region: "us-east-1".to_string(),
            bucket: "vpshell-sync".to_string(),
            prefix: "scope".to_string(),
            path_style,
            timeout_seconds: 10,
        };
        let path_style =
            ReqwestS3ObjectTransport::connect(config(true), credentials(), None).unwrap();
        assert_eq!(
            path_style.object_url("objects/a.oseg").unwrap().as_str(),
            "https://s3.example.test/vpshell-sync/scope/objects/a.oseg"
        );
        let virtual_hosted =
            ReqwestS3ObjectTransport::connect(config(false), credentials(), None).unwrap();
        assert_eq!(
            virtual_hosted
                .object_url("objects/a.oseg")
                .unwrap()
                .as_str(),
            "https://vpshell-sync.s3.example.test/scope/objects/a.oseg"
        );
        let ipv6 = Url::parse("https://[2001:db8::1]:9443/").unwrap();
        assert_eq!(canonical_host(&ipv6).unwrap(), "[2001:db8::1]:9443");
    }

    #[test]
    fn upload_reader_stops_after_cancellation() {
        let cancellation = ProviderCancellation::default();
        let mut upload = CancellableUpload::new(
            b"secret-free-fixture".to_vec(),
            cancellation.clone(),
        );
        cancellation.cancel();
        let mut buffer = [0u8; 8];
        assert_eq!(
            upload.read(&mut buffer).unwrap_err().kind(),
            std::io::ErrorKind::Interrupted
        );
    }

    #[test]
    fn real_s3_compatible_provider_when_configured() {
        let Some(endpoint) = env::var("VPSHELL_S3_TEST_ENDPOINT").ok() else {
            return;
        };
        let ca_path = env::var("VPSHELL_S3_TEST_CA").expect("fixture CA");
        let access_key_id = env::var("VPSHELL_S3_TEST_ACCESS_KEY_ID").expect("fixture access key");
        let secret_access_key =
            env::var("VPSHELL_S3_TEST_SECRET_ACCESS_KEY").expect("fixture secret key");
        let config = S3ProviderConfig {
            endpoint,
            region: "us-east-1".to_string(),
            bucket: "vpshell-ci".to_string(),
            prefix: "fixture-scope".to_string(),
            path_style: true,
            timeout_seconds: 10,
        };
        let credentials =
            S3Credentials::new(access_key_id, secret_access_key, None).expect("fixture credential");
        let ca = fs::read(ca_path).expect("fixture CA bytes");
        let transport = ReqwestS3ObjectTransport::connect(config.clone(), credentials, Some(&ca))
            .expect("transport");
        let provider = S3SyncProvider::connect(config, transport).expect("provider");
        let cancellation = ProviderCancellation::default();
        let key_a = format!("objects/{}.oseg", uuid::Uuid::new_v4());
        let key_b = format!("objects/{}.oseg", uuid::Uuid::new_v4());
        assert!(provider.put(&key_a, b"alpha", &cancellation).is_ok());
        assert!(provider.put(&key_b, b"bravo", &cancellation).is_ok());
        assert_eq!(provider.get(&key_a, &cancellation).unwrap(), b"alpha");
        let page = provider.list("objects/", None, 100, &cancellation).unwrap();
        assert!(page.objects.iter().any(|object| object.key == key_a));
        assert!(page.objects.iter().any(|object| object.key == key_b));
        assert_eq!(
            provider
                .put(&key_a, b"different", &cancellation)
                .unwrap_err()
                .code,
            ProviderErrorCode::Conflict
        );
    }
}
