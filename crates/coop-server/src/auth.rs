use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet, KeyOperations, PublicKeyUse};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest::redirect::Policy;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, RwLock};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const CREDENTIALS_FILE_MAX_BYTES: u64 = 1024 * 1024;
const PEPPER_FILE_MAX_BYTES: u64 = 4096;
const MAX_CREDENTIALS: usize = 10_000;
const MAX_BEARER_BYTES: usize = 16 * 1024;
const JWKS_MAX_BYTES: usize = 1024 * 1024;
const JWKS_MAX_KEYS: usize = 64;
const JWKS_UNKNOWN_KID_REFRESH_COOLDOWN: Duration = Duration::from_secs(10);
const DUMMY_CREDENTIAL: &[u8] = b"coop-invalid-credential";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    ApiKey,
    Jwt,
}

impl AuthMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::Jwt => "jwt",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    JobsSubmit,
    JobsRead,
    JobsCancel,
    ServiceRead,
    MetricsRead,
}

impl Scope {
    pub const ALL: [Self; 5] = [
        Self::JobsSubmit,
        Self::JobsRead,
        Self::JobsCancel,
        Self::ServiceRead,
        Self::MetricsRead,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JobsSubmit => "jobs:submit",
            Self::JobsRead => "jobs:read",
            Self::JobsCancel => "jobs:cancel",
            Self::ServiceRead => "service:read",
            Self::MetricsRead => "metrics:read",
        }
    }

    fn bit(self) -> u8 {
        match self {
            Self::JobsSubmit => 1 << 0,
            Self::JobsRead => 1 << 1,
            Self::JobsCancel => 1 << 2,
            Self::ServiceRead => 1 << 3,
            Self::MetricsRead => 1 << 4,
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScopeSet(u8);

impl ScopeSet {
    pub fn all() -> Self {
        Self(
            Scope::ALL
                .into_iter()
                .fold(0, |bits, scope| bits | scope.bit()),
        )
    }

    pub fn from_names(names: &[String]) -> Result<Self, String> {
        let mut scopes = Self::default();
        for name in names {
            let scope = Scope::parse(name)
                .ok_or_else(|| format!("unsupported credential scope {name:?}"))?;
            scopes.0 |= scope.bit();
        }
        Ok(scopes)
    }

    pub fn contains(self, scope: Scope) -> bool {
        self.0 & scope.bit() != 0
    }

    pub fn names(self) -> Vec<&'static str> {
        Scope::ALL
            .into_iter()
            .filter(|scope| self.contains(*scope))
            .map(Scope::as_str)
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthContext {
    pub tenant_id: String,
    pub principal_id: String,
    pub credential_id: Option<String>,
    pub method: AuthMethod,
    pub scopes: ScopeSet,
    pub expires_at_ms: Option<i64>,
}

impl AuthContext {
    pub fn legacy_api_key(tenant_id: String) -> Self {
        Self {
            principal_id: format!("legacy:{tenant_id}"),
            tenant_id,
            credential_id: None,
            method: AuthMethod::ApiKey,
            scopes: ScopeSet::all(),
            expires_at_ms: None,
        }
    }

    pub fn has_scope(&self, scope: Scope) -> bool {
        self.scopes.contains(scope)
    }

    fn is_expired(&self, at_ms: i64) -> bool {
        self.expires_at_ms.is_some_and(|expires| expires <= at_ms)
    }
}

fn earliest_authority_end_ms(
    expires_at_ms: Option<i64>,
    revoked_at_ms: Option<i64>,
) -> Option<i64> {
    match (expires_at_ms, revoked_at_ms) {
        (Some(expires), Some(revoked)) => Some(expires.min(revoked)),
        (Some(expires), None) => Some(expires),
        (None, Some(revoked)) => Some(revoked),
        (None, None) => None,
    }
}

#[derive(Debug, Clone)]
pub struct StreamTicket {
    pub job_id: String,
    pub auth: AuthContext,
    pub expires_at_ms: i64,
}

pub const STREAM_TICKET_TTL_MS: i64 = 30_000;

fn stream_ticket_expiry_ms(issued_at_ms: i64, authority_end_ms: Option<i64>) -> i64 {
    let ttl_end_ms = issued_at_ms.saturating_add(STREAM_TICKET_TTL_MS);
    authority_end_ms.map_or(ttl_end_ms, |authority_end| ttl_end_ms.min(authority_end))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialsDocument {
    version: u32,
    credentials: Vec<CredentialDocument>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialDocument {
    key_id: String,
    tenant_id: String,
    principal_id: String,
    digest_hmac_sha256: String,
    scopes: Vec<String>,
    created_at_ms: i64,
    #[serde(default)]
    expires_at_ms: Option<i64>,
    #[serde(default)]
    revoked_at_ms: Option<i64>,
}

#[derive(Debug)]
struct StoredCredential {
    key_id: String,
    tenant_id: String,
    principal_id: String,
    digest: [u8; 32],
    scopes: ScopeSet,
    expires_at_ms: Option<i64>,
    revoked_at_ms: Option<i64>,
}

struct CredentialStoreInner {
    pepper: [u8; 32],
    dummy_digest: [u8; 32],
    by_id: HashMap<String, StoredCredential>,
}

impl Drop for CredentialStoreInner {
    fn drop(&mut self) {
        self.pepper.zeroize();
        self.dummy_digest.zeroize();
        for credential in self.by_id.values_mut() {
            credential.digest.zeroize();
        }
    }
}

/// Immutable, indexed production credential set. The raw API-key secret is
/// never represented here: the file stores only a public key id and a
/// peppered HMAC-SHA-256 verifier.
#[derive(Clone, Default)]
pub struct CredentialStore(Option<Arc<CredentialStoreInner>>);

impl std::fmt::Debug for CredentialStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialStore")
            .field("credentials", &self.len())
            .field("secrets", &"redacted")
            .finish()
    }
}

impl CredentialStore {
    pub fn load(
        credentials_path: &Path,
        pepper_path: &Path,
        production: bool,
    ) -> Result<Self, String> {
        validate_credential_file(credentials_path, "ROOKHOLD_CREDENTIALS_FILE", production)?;
        validate_credential_file(pepper_path, "ROOKHOLD_CREDENTIAL_PEPPER_FILE", production)?;

        let pepper_text = read_bounded_utf8(
            pepper_path,
            "ROOKHOLD_CREDENTIAL_PEPPER_FILE",
            PEPPER_FILE_MAX_BYTES,
        )?;
        let pepper = decode_hex_32(pepper_text.trim())
            .map_err(|error| format!("ROOKHOLD_CREDENTIAL_PEPPER_FILE {error}"))?;
        let credentials_text = read_bounded_utf8(
            credentials_path,
            "ROOKHOLD_CREDENTIALS_FILE",
            CREDENTIALS_FILE_MAX_BYTES,
        )?;
        let document: CredentialsDocument = serde_json::from_str(&credentials_text)
            .map_err(|error| format!("invalid ROOKHOLD_CREDENTIALS_FILE JSON: {error}"))?;
        if document.version != 1 {
            return Err(format!(
                "unsupported ROOKHOLD_CREDENTIALS_FILE version {}; expected 1",
                document.version
            ));
        }
        if document.credentials.is_empty() {
            return Err("ROOKHOLD_CREDENTIALS_FILE contains no credentials".to_string());
        }
        if document.credentials.len() > MAX_CREDENTIALS {
            return Err(format!(
                "ROOKHOLD_CREDENTIALS_FILE contains too many credentials (maximum {MAX_CREDENTIALS})"
            ));
        }

        let mut by_id = HashMap::with_capacity(document.credentials.len());
        for entry in document.credentials {
            validate_key_id(&entry.key_id)?;
            validate_identity("tenant_id", &entry.tenant_id)?;
            validate_identity("principal_id", &entry.principal_id)?;
            if entry.created_at_ms < 0 {
                return Err(format!(
                    "credential {:?} has a negative created_at_ms",
                    entry.key_id
                ));
            }
            if entry
                .expires_at_ms
                .is_some_and(|value| value <= entry.created_at_ms)
            {
                return Err(format!(
                    "credential {:?} expires_at_ms must be after created_at_ms",
                    entry.key_id
                ));
            }
            if entry
                .revoked_at_ms
                .is_some_and(|value| value < entry.created_at_ms)
            {
                return Err(format!(
                    "credential {:?} revoked_at_ms must not precede created_at_ms",
                    entry.key_id
                ));
            }
            let digest = decode_hex_32(&entry.digest_hmac_sha256).map_err(|error| {
                format!("credential {:?} digest_hmac_sha256 {error}", entry.key_id)
            })?;
            let scopes = ScopeSet::from_names(&entry.scopes)
                .map_err(|error| format!("credential {:?}: {error}", entry.key_id))?;
            let key_id = entry.key_id.clone();
            let credential = StoredCredential {
                key_id: entry.key_id,
                tenant_id: entry.tenant_id,
                principal_id: entry.principal_id,
                digest,
                scopes,
                expires_at_ms: entry.expires_at_ms,
                revoked_at_ms: entry.revoked_at_ms,
            };
            if by_id.insert(key_id.clone(), credential).is_some() {
                return Err(format!(
                    "ROOKHOLD_CREDENTIALS_FILE contains duplicate key_id {key_id:?}"
                ));
            }
        }

        let dummy_digest = credential_digest(&pepper, DUMMY_CREDENTIAL);
        Ok(Self(Some(Arc::new(CredentialStoreInner {
            pepper,
            dummy_digest,
            by_id,
        }))))
    }

    pub fn len(&self) -> usize {
        self.0.as_ref().map_or(0, |inner| inner.by_id.len())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(crate) fn matches_active_credential(&self, presented: &str) -> bool {
        self.authenticate(presented, now_ms()).is_some()
    }

    fn authenticate(&self, presented: &str, at_ms: i64) -> Option<AuthContext> {
        let inner = self.0.as_ref()?;
        let key_id = credential_key_id(presented);
        let candidate_digest = credential_digest(&inner.pepper, presented.as_bytes());
        let expected = key_id
            .and_then(|key_id| inner.by_id.get(key_id))
            .map_or(&inner.dummy_digest, |credential| &credential.digest);
        let digest_matches = bool::from(candidate_digest.ct_eq(expected));
        let credential = key_id.and_then(|key_id| inner.by_id.get(key_id))?;
        let authority_end_ms =
            earliest_authority_end_ms(credential.expires_at_ms, credential.revoked_at_ms);
        if !digest_matches || authority_end_ms.is_some_and(|end| end <= at_ms) {
            return None;
        }
        Some(AuthContext {
            tenant_id: credential.tenant_id.clone(),
            principal_id: credential.principal_id.clone(),
            credential_id: Some(credential.key_id.clone()),
            method: AuthMethod::ApiKey,
            scopes: credential.scopes,
            expires_at_ms: authority_end_ms,
        })
    }
}

#[derive(Clone)]
pub struct JwtConfig {
    pub issuer: String,
    pub audience: String,
    pub jwks_url: Url,
    pub tenant_claim: String,
    pub tenant_map: HashMap<String, String>,
    pub algorithms: Vec<Algorithm>,
    pub jwks_ttl: Duration,
    pub max_token_age: Duration,
}

impl std::fmt::Debug for JwtConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtConfig")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("jwks_url", &self.jwks_url)
            .field("tenant_claim", &self.tenant_claim)
            .field("tenant_mappings", &self.tenant_map.len())
            .field("algorithms", &self.algorithms)
            .field("jwks_ttl", &self.jwks_ttl)
            .field("max_token_age", &self.max_token_age)
            .finish()
    }
}

impl JwtConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn parse(
        issuer: &str,
        audience: &str,
        jwks_url: &str,
        tenant_claim: &str,
        tenant_map: &str,
        algorithms: &str,
        jwks_ttl_seconds: u64,
        max_token_age_seconds: u64,
    ) -> Result<Self, String> {
        validate_https_url("ROOKHOLD_OIDC_ISSUER", issuer)?;
        validate_https_url("ROOKHOLD_OIDC_AUDIENCE", audience)?;
        let jwks_url = validate_https_url("ROOKHOLD_OIDC_JWKS_URL", jwks_url)?;
        validate_claim_name(tenant_claim)?;
        if matches!(
            tenant_claim,
            "iss" | "sub" | "aud" | "exp" | "nbf" | "iat" | "jti" | "client_id" | "scope"
        ) {
            return Err("ROOKHOLD_OIDC_TENANT_CLAIM must be a distinct private claim".to_string());
        }

        let mut parsed_map = HashMap::new();
        for mapping in tenant_map.split(',') {
            let mapping = mapping.trim();
            if mapping.is_empty() {
                continue;
            }
            let (external, internal) = mapping.split_once('=').ok_or_else(|| {
                "ROOKHOLD_OIDC_TENANT_MAP entries must use external=internal syntax".to_string()
            })?;
            let external = external.trim();
            let internal = internal.trim();
            validate_identity("OIDC external tenant", external)?;
            validate_identity("OIDC internal tenant", internal)?;
            if parsed_map
                .insert(external.to_string(), internal.to_string())
                .is_some()
            {
                return Err(format!(
                    "ROOKHOLD_OIDC_TENANT_MAP contains duplicate external tenant {external:?}"
                ));
            }
        }
        if parsed_map.is_empty() {
            return Err("ROOKHOLD_OIDC_TENANT_MAP must contain at least one mapping".to_string());
        }

        let mut parsed_algorithms = Vec::new();
        for name in algorithms
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            let algorithm = Algorithm::from_str(name)
                .map_err(|_| format!("unsupported ROOKHOLD_OIDC_ALGORITHMS value {name:?}"))?;
            if matches!(
                algorithm,
                Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
            ) {
                return Err("ROOKHOLD_OIDC_ALGORITHMS must use asymmetric algorithms".to_string());
            }
            if !parsed_algorithms.contains(&algorithm) {
                parsed_algorithms.push(algorithm);
            }
        }
        if parsed_algorithms.is_empty() {
            return Err("ROOKHOLD_OIDC_ALGORITHMS must not be empty".to_string());
        }
        if !(60..=3600).contains(&jwks_ttl_seconds) {
            return Err("ROOKHOLD_OIDC_JWKS_TTL_SECONDS must be between 60 and 3600".to_string());
        }
        if !(60..=86_400).contains(&max_token_age_seconds) {
            return Err(
                "ROOKHOLD_OIDC_MAX_TOKEN_AGE_SECONDS must be between 60 and 86400".to_string(),
            );
        }

        Ok(Self {
            issuer: issuer.to_string(),
            audience: audience.to_string(),
            jwks_url,
            tenant_claim: tenant_claim.to_string(),
            tenant_map: parsed_map,
            algorithms: parsed_algorithms,
            jwks_ttl: Duration::from_secs(jwks_ttl_seconds),
            max_token_age: Duration::from_secs(max_token_age_seconds),
        })
    }

    pub fn protected_resource_metadata(&self) -> Value {
        serde_json::json!({
            "resource": self.audience,
            "authorization_servers": [self.issuer],
            "bearer_methods_supported": ["header"],
            "scopes_supported": Scope::ALL.map(Scope::as_str),
            "resource_name": "Rookhold execution gateway"
        })
    }
}

#[derive(Clone)]
struct CachedJwtKey {
    decoding_key: DecodingKey,
    algorithm: Option<Algorithm>,
    family: JwtKeyFamily,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JwtKeyFamily {
    Rsa,
    Ec,
    Ed,
}

struct JwksCache {
    keys: HashMap<String, CachedJwtKey>,
    valid_until: Instant,
    last_refresh_attempt: Option<Instant>,
}

#[derive(Clone, Copy)]
enum RefreshReason<'a> {
    Expired,
    UnknownKid(&'a str),
}

type JwksFuture<'a> =
    Pin<Box<dyn Future<Output = Result<HashMap<String, CachedJwtKey>, String>> + Send + 'a>>;

trait JwksSource: Send + Sync {
    fn fetch(&self) -> JwksFuture<'_>;
}

#[cfg(test)]
struct StaticJwksSource {
    keys: HashMap<String, CachedJwtKey>,
}

#[cfg(test)]
impl JwksSource for StaticJwksSource {
    fn fetch(&self) -> JwksFuture<'_> {
        Box::pin(async move { Ok(self.keys.clone()) })
    }
}

struct HttpJwksSource {
    client: Client,
    url: Url,
    algorithms: Vec<Algorithm>,
}

impl JwksSource for HttpJwksSource {
    fn fetch(&self) -> JwksFuture<'_> {
        Box::pin(async move {
            let response = self
                .client
                .get(self.url.clone())
                .header(
                    reqwest::header::ACCEPT,
                    "application/jwk-set+json, application/json",
                )
                .send()
                .await
                .map_err(|error| format!("OIDC JWKS request failed: {error}"))?;
            if !response.status().is_success() {
                return Err(format!(
                    "OIDC JWKS endpoint returned HTTP {}",
                    response.status()
                ));
            }
            if response
                .content_length()
                .is_some_and(|length| length > JWKS_MAX_BYTES as u64)
            {
                return Err("OIDC JWKS response exceeds the 1 MiB limit".to_string());
            }
            let mut body = Vec::new();
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|error| format!("OIDC JWKS body failed: {error}"))?;
                if body.len().saturating_add(chunk.len()) > JWKS_MAX_BYTES {
                    return Err("OIDC JWKS response exceeds the 1 MiB limit".to_string());
                }
                body.extend_from_slice(&chunk);
            }
            parse_jwks(&body, &self.algorithms)
        })
    }
}

pub struct JwtVerifier {
    config: JwtConfig,
    source: Arc<dyn JwksSource>,
    cache: RwLock<JwksCache>,
    refresh_lock: Mutex<()>,
}

impl std::fmt::Debug for JwtVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtVerifier")
            .field("config", &self.config)
            .field("cache", &"bounded JWKS cache")
            .finish()
    }
}

impl JwtVerifier {
    pub async fn build(config: JwtConfig) -> Result<Self, String> {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .redirect(Policy::none())
            .user_agent(concat!("rookhold/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| format!("cannot build OIDC JWKS client: {error}"))?;
        let source = Arc::new(HttpJwksSource {
            client,
            url: config.jwks_url.clone(),
            algorithms: config.algorithms.clone(),
        });
        let verifier = Self {
            config,
            source,
            cache: RwLock::new(JwksCache {
                keys: HashMap::new(),
                valid_until: Instant::now(),
                last_refresh_attempt: None,
            }),
            refresh_lock: Mutex::new(()),
        };
        verifier.refresh(RefreshReason::Expired).await?;
        Ok(verifier)
    }

    pub(crate) async fn authenticate(&self, token: &str) -> Result<AuthContext, String> {
        validate_raw_jose_header(token)?;
        let header = decode_header(token).map_err(|_| "malformed JWT access token".to_string())?;
        if header.typ.as_deref() != Some("at+jwt")
            && header.typ.as_deref() != Some("application/at+jwt")
        {
            return Err("JWT access token typ must be at+jwt".to_string());
        }
        if !self.config.algorithms.contains(&header.alg) {
            return Err("JWT access token algorithm is not allowed".to_string());
        }
        if header.jku.is_some()
            || header.jwk.is_some()
            || header.x5u.is_some()
            || header.x5c.is_some()
        {
            return Err(
                "JWT access token contains unsupported key or critical headers".to_string(),
            );
        }
        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| "JWT access token is missing kid".to_string())?;
        validate_jwt_kid(kid)?;
        let key = self.key_for(kid).await?;
        if Some(key.family) != jwt_algorithm_family(header.alg) {
            return Err("JWT key family does not match the token algorithm".to_string());
        }
        if key
            .algorithm
            .is_some_and(|algorithm| algorithm != header.alg)
        {
            return Err("JWT key algorithm does not match the token algorithm".to_string());
        }

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.set_audience(&[self.config.audience.as_str()]);
        validation.set_required_spec_claims(&["iss", "sub", "aud", "exp"]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = 60;
        let token = decode::<JwtClaims>(token, &key.decoding_key, &validation)
            .map_err(|_| "JWT signature or registered claims are invalid".to_string())?;
        let claims = token.claims;
        if claims.iss != self.config.issuer || claims.sub.is_empty() {
            return Err("JWT issuer or subject is invalid".to_string());
        }
        validate_token_identifier("sub", &claims.sub)?;
        validate_token_identifier("client_id", &claims.client_id)?;
        validate_token_identifier("jti", &claims.jti)?;
        let now = now_seconds();
        if claims.iat > now.saturating_add(60)
            || claims.exp <= claims.iat
            || claims.exp.saturating_sub(claims.iat) > self.config.max_token_age.as_secs()
        {
            return Err("JWT token age is outside local policy".to_string());
        }
        if claims.nbf.is_some_and(|nbf| nbf > now.saturating_add(60)) {
            return Err("JWT not-before time is invalid".to_string());
        }
        if !audience_contains(&claims.aud, &self.config.audience) {
            return Err("JWT audience is invalid".to_string());
        }
        if claims.scope.is_empty()
            || claims
                .scope
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b'\t')
        {
            return Err("JWT scope claim is invalid".to_string());
        }
        let scope_names = claims
            .scope
            .split(' ')
            .map(str::to_string)
            .collect::<Vec<_>>();
        if scope_names.iter().any(String::is_empty) {
            return Err("JWT scope claim is not canonically space-delimited".to_string());
        }
        let scopes = ScopeSet::from_names(&scope_names)?;
        let external_tenant = claims
            .extra
            .get(&self.config.tenant_claim)
            .and_then(Value::as_str)
            .ok_or_else(|| "JWT tenant claim is missing or not a string".to_string())?;
        let tenant_id = self
            .config
            .tenant_map
            .get(external_tenant)
            .cloned()
            .ok_or_else(|| "JWT tenant is not provisioned".to_string())?;
        let principal_id = oidc_principal_id(&claims.iss, &claims.sub, &claims.client_id);
        let expires_at_ms = i64::try_from(claims.exp)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1000))
            .ok_or_else(|| "JWT expiration is out of range".to_string())?;
        Ok(AuthContext {
            tenant_id,
            principal_id,
            credential_id: None,
            method: AuthMethod::Jwt,
            scopes,
            expires_at_ms: Some(expires_at_ms),
        })
    }

    async fn key_for(&self, kid: &str) -> Result<CachedJwtKey, String> {
        let refresh_reason = {
            let cache = self.cache.read().await;
            if cache.valid_until > Instant::now() {
                if let Some(key) = cache.keys.get(kid).cloned() {
                    return Ok(key);
                }
                RefreshReason::UnknownKid(kid)
            } else {
                RefreshReason::Expired
            }
        };
        self.refresh(refresh_reason).await?;
        self.cache
            .read()
            .await
            .keys
            .get(kid)
            .cloned()
            .ok_or_else(|| "JWT kid is not present in the configured JWKS".to_string())
    }

    async fn refresh(&self, reason: RefreshReason<'_>) -> Result<(), String> {
        let _guard = self.refresh_lock.lock().await;
        let now = Instant::now();
        {
            let cache = self.cache.read().await;
            if cache.valid_until > now {
                match reason {
                    RefreshReason::Expired => return Ok(()),
                    RefreshReason::UnknownKid(kid) if cache.keys.contains_key(kid) => return Ok(()),
                    RefreshReason::UnknownKid(_) => {}
                }
            } else if !cache.keys.is_empty()
                && cache.last_refresh_attempt.is_some_and(|last| {
                    now.duration_since(last) < JWKS_UNKNOWN_KID_REFRESH_COOLDOWN
                })
            {
                return Err("OIDC JWKS refresh is cooling down after a recent attempt".to_string());
            }
            if matches!(reason, RefreshReason::UnknownKid(_))
                && cache.last_refresh_attempt.is_some_and(|last| {
                    now.duration_since(last) < JWKS_UNKNOWN_KID_REFRESH_COOLDOWN
                })
            {
                return Ok(());
            }
        }
        self.cache.write().await.last_refresh_attempt = Some(now);
        let keys = self.source.fetch().await?;
        let mut cache = self.cache.write().await;
        cache.keys = keys;
        cache.valid_until = Instant::now() + self.config.jwks_ttl;
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct JwtClaims {
    iss: String,
    sub: String,
    aud: Value,
    exp: u64,
    client_id: String,
    iat: u64,
    jti: String,
    scope: String,
    #[serde(default)]
    nbf: Option<u64>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

fn parse_jwks(
    body: &[u8],
    allowed_algorithms: &[Algorithm],
) -> Result<HashMap<String, CachedJwtKey>, String> {
    let set: JwkSet =
        serde_json::from_slice(body).map_err(|error| format!("invalid OIDC JWKS JSON: {error}"))?;
    if set.keys.is_empty() || set.keys.len() > JWKS_MAX_KEYS {
        return Err(format!(
            "OIDC JWKS must contain between 1 and {JWKS_MAX_KEYS} keys"
        ));
    }
    let mut keys = HashMap::new();
    for jwk in &set.keys {
        if jwk
            .common
            .public_key_use
            .as_ref()
            .is_some_and(|usage| !matches!(usage, PublicKeyUse::Signature))
        {
            continue;
        }
        if jwk
            .common
            .key_operations
            .as_ref()
            .is_some_and(|operations| {
                !operations
                    .iter()
                    .any(|operation| matches!(operation, KeyOperations::Verify))
            })
        {
            continue;
        }
        let family = match &jwk.algorithm {
            AlgorithmParameters::RSA(_) => JwtKeyFamily::Rsa,
            AlgorithmParameters::EllipticCurve(_) => JwtKeyFamily::Ec,
            AlgorithmParameters::OctetKeyPair(_) => JwtKeyFamily::Ed,
            AlgorithmParameters::OctetKey(_) => continue,
            // jsonwebtoken 11 added `Other` and marked the enum
            // non-exhaustive: unknown key types cannot be verified by
            // known code, so skip them like symmetric keys (deny by
            // default) rather than accepting them into the cache.
            _ => continue,
        };
        let Some(kid) = jwk.common.key_id.as_deref() else {
            continue;
        };
        validate_jwt_kid(kid)?;
        let algorithm = jwk
            .common
            .key_algorithm
            .map(|algorithm| Algorithm::from_str(&algorithm.to_string()))
            .transpose()
            .map_err(|_| format!("OIDC JWKS key {kid:?} has an unsupported algorithm"))?;
        if algorithm.is_some_and(|algorithm| !allowed_algorithms.contains(&algorithm)) {
            continue;
        }
        let decoding_key = DecodingKey::from_jwk(jwk)
            .map_err(|_| format!("OIDC JWKS key {kid:?} cannot be used for verification"))?;
        if keys
            .insert(
                kid.to_string(),
                CachedJwtKey {
                    decoding_key,
                    algorithm,
                    family,
                },
            )
            .is_some()
        {
            return Err(format!("OIDC JWKS contains duplicate kid {kid:?}"));
        }
    }
    if keys.is_empty() {
        return Err("OIDC JWKS contains no eligible asymmetric verification keys".to_string());
    }
    Ok(keys)
}

fn validate_https_url(setting: &str, value: &str) -> Result<Url, String> {
    let url =
        Url::parse(value).map_err(|error| format!("{setting} is not a valid URL: {error}"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
    {
        return Err(format!(
            "{setting} must be an HTTPS URL without credentials, query, or fragment",
        ));
    }
    Ok(url)
}

fn validate_claim_name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'/' | b'_' | b'-')
        })
    {
        return Err("ROOKHOLD_OIDC_TENANT_CLAIM is not a safe claim name".to_string());
    }
    Ok(())
}

fn validate_jwt_kid(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
    {
        return Err("JWT kid must contain 1-128 safe printable ASCII characters".to_string());
    }
    Ok(())
}

fn validate_raw_jose_header(token: &str) -> Result<(), String> {
    let mut segments = token.split('.');
    let encoded_header = segments
        .next()
        .filter(|segment| !segment.is_empty())
        .ok_or_else(|| "malformed JWT access token".to_string())?;
    if segments.next().is_none() || segments.next().is_none() || segments.next().is_some() {
        return Err("malformed JWT access token".to_string());
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded_header)
        .map_err(|_| "malformed JWT JOSE header".to_string())?;
    let header: Value = serde_json::from_slice(&decoded)
        .map_err(|_| "malformed JWT JOSE header JSON".to_string())?;
    let header = header
        .as_object()
        .ok_or_else(|| "JWT JOSE header must be an object".to_string())?;
    for unsupported in ["jku", "jwk", "x5u", "x5c", "crit", "enc", "zip"] {
        if header.contains_key(unsupported) {
            return Err(format!(
                "JWT access token contains unsupported JOSE header {unsupported:?}"
            ));
        }
    }
    Ok(())
}

fn jwt_algorithm_family(algorithm: Algorithm) -> Option<JwtKeyFamily> {
    match algorithm {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => Some(JwtKeyFamily::Rsa),
        Algorithm::ES256 | Algorithm::ES384 => Some(JwtKeyFamily::Ec),
        Algorithm::EdDSA => Some(JwtKeyFamily::Ed),
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => None,
        // `Algorithm` is non-exhaustive since jsonwebtoken 11: future
        // algorithms have no known family, so verification rejects them
        // at the family check (fail closed).
        _ => None,
    }
}

fn validate_token_identifier(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(format!(
            "JWT {field} is empty, oversized, or contains controls"
        ));
    }
    Ok(())
}

fn audience_contains(audience: &Value, expected: &str) -> bool {
    match audience {
        Value::String(value) => value == expected,
        Value::Array(values) => values.iter().any(|value| value.as_str() == Some(expected)),
        _ => false,
    }
}

fn oidc_principal_id(issuer: &str, subject: &str, client_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"coop-oidc-principal-v1\0");
    digest.update(issuer.as_bytes());
    digest.update(b"\0");
    digest.update(subject.as_bytes());
    digest.update(b"\0");
    digest.update(client_id.as_bytes());
    format!("oidc:{:x}", digest.finalize())
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Mint a high-entropy, one-use WebSocket credential. The derived grant keeps
/// the complete authorization context so a ticket cannot gain scopes or lose
/// actor attribution while crossing the browser WebSocket handshake.
pub fn issue_stream_ticket(
    state: &crate::AppState,
    job_id: &str,
    auth: &AuthContext,
) -> (String, i64) {
    let issued_at_ms = now_ms();
    let expires_at_ms = stream_ticket_expiry_ms(issued_at_ms, auth.expires_at_ms);
    let token = format!(
        "{}{}",
        uuid::Uuid::now_v7().simple(),
        uuid::Uuid::now_v7().simple()
    );
    state
        .stream_tickets
        .retain(|_, ticket| ticket.expires_at_ms > issued_at_ms);
    state.stream_tickets.insert(
        token.clone(),
        StreamTicket {
            job_id: job_id.to_string(),
            auth: auth.clone(),
            expires_at_ms,
        },
    );
    (token, expires_at_ms)
}

fn legacy_key_digest(key: &str) -> [u8; 32] {
    Sha256::digest(key.as_bytes()).into()
}

/// Constant-time equality over fixed-size digests.
fn ct_digest_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    bool::from(a.ct_eq(b))
}

/// Legacy compatibility deliberately scans every configured key. New
/// production credentials use the indexed, peppered verifier above.
fn authenticate_legacy(api_keys: &HashMap<String, String>, presented: &str) -> Option<AuthContext> {
    let presented = legacy_key_digest(presented);
    let mut tenant = None;
    for (candidate, candidate_tenant) in api_keys {
        if ct_digest_eq(&presented, &legacy_key_digest(candidate)) {
            tenant = Some(candidate_tenant.clone());
        }
    }
    tenant.map(AuthContext::legacy_api_key)
}

enum Bearer<'a> {
    Missing,
    Malformed,
    Present(&'a str),
}

fn extract_bearer(req: &Request) -> Bearer<'_> {
    let Some(value) = req.headers().get(header::AUTHORIZATION) else {
        return Bearer::Missing;
    };
    let Ok(value) = value.to_str() else {
        return Bearer::Malformed;
    };
    if value.len() > MAX_BEARER_BYTES {
        return Bearer::Malformed;
    }
    let Some((scheme, credential)) = value.split_once(' ') else {
        return Bearer::Malformed;
    };
    if !scheme.eq_ignore_ascii_case("bearer")
        || credential.is_empty()
        || credential.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Bearer::Malformed;
    }
    Bearer::Present(credential)
}

fn extract_query_param(req: &Request, name: &str) -> Option<String> {
    let query = req.uri().query()?;
    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            if key == name {
                return urldecode(value);
            }
        }
    }
    None
}

fn urldecode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                index += 3;
            }
            b'%' => return None,
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

pub async fn middleware(
    State(state): State<crate::AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    match extract_bearer(&req) {
        Bearer::Present(presented) => {
            let at_ms = now_ms();
            let mut authenticated = authenticate_local(
                &state.cfg.credentials,
                &state.cfg.api_keys,
                presented,
                at_ms,
            );
            if authenticated.is_none() && presented.matches('.').count() == 2 {
                if let Some(verifier) = &state.jwt_verifier {
                    authenticated = verifier.authenticate(presented).await.ok();
                }
            }
            return match authenticated {
                Some(auth) => {
                    req.extensions_mut().insert(auth);
                    next.run(req).await
                }
                None => unauthorized(
                    "invalid_api_key",
                    "invalid or inactive bearer credential",
                    Some("invalid_token"),
                ),
            };
        }
        Bearer::Malformed => {
            return unauthorized(
                "invalid_authorization",
                "malformed bearer authorization header",
                Some("invalid_request"),
            )
        }
        Bearer::Missing => {}
    }

    let path = req.uri().path().to_string();
    if path.ends_with("/stream") {
        if let Some(token) = extract_query_param(&req, "ticket") {
            if let Some(grant) = state.stream_tickets.get(&token).map(|entry| entry.clone()) {
                let expected_path = format!("/v1/jobs/{}/stream", grant.job_id);
                let at_ms = now_ms();
                if grant.expires_at_ms > at_ms
                    && !grant.auth.is_expired(at_ms)
                    && path == expected_path
                    && state.stream_tickets.remove(&token).is_some()
                {
                    req.extensions_mut().insert(grant.auth);
                    return next.run(req).await;
                }
                if grant.expires_at_ms <= at_ms || grant.auth.is_expired(at_ms) {
                    state.stream_tickets.remove(&token);
                }
            }
            return unauthorized(
                "invalid_stream_ticket",
                "stream ticket is invalid, expired, or already used",
                Some("invalid_token"),
            );
        }

        // Development-only v0.1 compatibility. Production never accepts a
        // long-lived credential in a URL.
        if !state.cfg.production {
            if let Some(key) = extract_query_param(&req, "key") {
                let authenticated =
                    authenticate_local(&state.cfg.credentials, &state.cfg.api_keys, &key, now_ms());
                return match authenticated {
                    Some(auth) => {
                        tracing::warn!("deprecated WebSocket ?key= authentication used");
                        req.extensions_mut().insert(auth);
                        next.run(req).await
                    }
                    None => unauthorized(
                        "invalid_api_key",
                        "invalid or inactive bearer credential",
                        Some("invalid_token"),
                    ),
                };
            }
        }
    }

    unauthorized("missing_api_key", "missing bearer credential", None)
}

/// Sensitive authenticated API responses must never be retained by browser,
/// intermediary, or shared caches. This layer intentionally wraps auth and
/// scope failures as well as successful responses.
pub async fn no_store(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

async fn require_scope(req: Request, next: Next, scope: Scope) -> Response {
    let Some(auth) = req.extensions().get::<AuthContext>() else {
        return unauthorized(
            "missing_auth_context",
            "authenticated request context is missing",
            None,
        );
    };
    if !auth.has_scope(scope) {
        return insufficient_scope(scope);
    }
    next.run(req).await
}

pub async fn require_jobs_submit(req: Request, next: Next) -> Response {
    require_scope(req, next, Scope::JobsSubmit).await
}

pub async fn require_jobs_read(req: Request, next: Next) -> Response {
    require_scope(req, next, Scope::JobsRead).await
}

pub async fn require_jobs_cancel(req: Request, next: Next) -> Response {
    require_scope(req, next, Scope::JobsCancel).await
}

pub async fn require_service_read(req: Request, next: Next) -> Response {
    require_scope(req, next, Scope::ServiceRead).await
}

pub async fn require_metrics_read(req: Request, next: Next) -> Response {
    require_scope(req, next, Scope::MetricsRead).await
}

pub(crate) fn unauthorized(code: &str, message: &str, error: Option<&str>) -> Response {
    let mut response = crate::routes::api_error(StatusCode::UNAUTHORIZED, code, message, false);
    let challenge = error.map_or_else(
        || "Bearer realm=\"rookhold\"".to_string(),
        |error| format!("Bearer realm=\"rookhold\", error=\"{error}\""),
    );
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

fn insufficient_scope(scope: Scope) -> Response {
    let mut response = crate::routes::api_error(
        StatusCode::FORBIDDEN,
        "insufficient_scope",
        format!("credential requires the {} scope", scope.as_str()),
        false,
    );
    let challenge = format!(
        "Bearer realm=\"rookhold\", error=\"insufficient_scope\", scope=\"{}\"",
        scope.as_str()
    );
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

fn credential_key_id(value: &str) -> Option<&str> {
    let (key_id, secret) = value.strip_prefix("coop_")?.split_once('_')?;
    (validate_key_id(key_id).is_ok() && secret.len() >= 32).then_some(key_id)
}

fn authenticate_local(
    credentials: &CredentialStore,
    legacy: &HashMap<String, String>,
    presented: &str,
    at_ms: i64,
) -> Option<AuthContext> {
    if !credentials.is_empty() && credential_key_id(presented).is_some() {
        credentials.authenticate(presented, at_ms)
    } else {
        authenticate_legacy(legacy, presented)
    }
}

fn credential_digest(pepper: &[u8; 32], credential: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(pepper).expect("HMAC accepts a 32-byte key");
    mac.update(credential);
    mac.finalize().into_bytes().into()
}

fn validate_key_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(
            "credential key_id must be 1-64 ASCII alphanumeric or '-' characters".to_string(),
        );
    }
    Ok(())
}

pub(crate) fn validate_identity(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
    {
        return Err(format!(
            "credential {field} must contain 1-128 safe printable ASCII characters"
        ));
    }
    Ok(())
}

fn validate_credential_file(path: &Path, setting: &str, production: bool) -> Result<(), String> {
    if production && !path.is_absolute() {
        return Err(format!("{setting} must be an absolute path in production"));
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {setting} {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "{setting} {} must be a regular non-symlink file",
            path.display()
        ));
    }
    #[cfg(unix)]
    if production {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != 0 || metadata.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "{setting} {} must be root-owned and inaccessible to group/other users",
                path.display()
            ));
        }
        for ancestor in path.ancestors().skip(1) {
            let ancestor_metadata = std::fs::symlink_metadata(ancestor).map_err(|error| {
                format!(
                    "cannot inspect {setting} ancestor {}: {error}",
                    ancestor.display()
                )
            })?;
            if ancestor_metadata.file_type().is_symlink()
                || !ancestor_metadata.is_dir()
                || ancestor_metadata.uid() != 0
                || ancestor_metadata.permissions().mode() & 0o022 != 0
            {
                return Err(format!(
                    "{setting} must traverse only root-owned, non-writable real directories; {} is insecure",
                    ancestor.display()
                ));
            }
        }
    }
    #[cfg(not(unix))]
    if production {
        return Err(format!(
            "{setting} production ownership checks require Unix; use legacy development credentials on this platform"
        ));
    }
    Ok(())
}

fn read_bounded_utf8(path: &Path, setting: &str, max_bytes: u64) -> Result<String, String> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("cannot inspect {setting} {}: {error}", path.display()))?;
    if metadata.len() > max_bytes {
        return Err(format!(
            "{setting} {} exceeds the {max_bytes}-byte limit",
            path.display()
        ));
    }
    let bytes = std::fs::read(path)
        .map_err(|error| format!("cannot read {setting} {}: {error}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!(
            "{setting} {} exceeded the {max_bytes}-byte limit while reading",
            path.display()
        ));
    }
    String::from_utf8(bytes).map_err(|_| format!("{setting} {} must be UTF-8", path.display()))
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], &'static str> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("must be exactly 64 hexadecimal characters");
    }
    let mut decoded = [0_u8; 32];
    for (index, slot) in decoded.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "contains invalid hexadecimal")?;
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use jsonwebtoken::jwk::Jwk;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Semaphore;
    use tower::ServiceExt;

    const TEST_RSA_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDJETqse41HRBsc
7cfcq3ak4oZWFCoZlcic525A3FfO4qW9BMtRO/iXiyCCHn8JhiL9y8j5JdVP2Q9Z
IpfElcFd3/guS9w+5RqQGgCR+H56IVUyHZWtTJbKPcwWXQdNUX0rBFcsBzCRESJL
eelOEdHIjG7LRkx5l/FUvlqsyHDVJEQsHwegZ8b8C0fz0EgT2MMEdn10t6Ur1rXz
jMB/wvCg8vG8lvciXmedyo9xJ8oMOh0wUEgxziVDMMovmC+aJctcHUAYubwoGN8T
yzcvnGqL7JSh36Pwy28iPzXZ2RLhAyJFU39vLaHdljwthUaupldlNyCfa6Ofy4qN
ctlUPlN1AgMBAAECggEAdESTQjQ70O8QIp1ZSkCYXeZjuhj081CK7jhhp/4ChK7J
GlFQZMwiBze7d6K84TwAtfQGZhQ7km25E1kOm+3hIDCoKdVSKch/oL54f/BK6sKl
qlIzQEAenho4DuKCm3I4yAw9gEc0DV70DuMTR0LEpYyXcNJY3KNBOTjN5EYQAR9s
2MeurpgK2MdJlIuZaIbzSGd+diiz2E6vkmcufJLtmYUT/k/ddWvEtz+1DnO6bRHh
xuuDMeJA/lGB/EYloSLtdyCF6sII6C6slJJtgfb0bPy7l8VtL5iDyz46IKyzdyzW
tKAn394dm7MYR1RlUBEfqFUyNK7C+pVMVoTwCC2V4QKBgQD64syfiQ2oeUlLYDm4
CcKSP3RnES02bcTyEDFSuGyyS1jldI4A8GXHJ/lG5EYgiYa1RUivge4lJrlNfjyf
dV230xgKms7+JiXqag1FI+3mqjAgg4mYiNjaao8N8O3/PD59wMPeWYImsWXNyeHS
55rUKiHERtCcvdzKl4u35ZtTqQKBgQDNKnX2bVqOJ4WSqCgHRhOm386ugPHfy+8j
m6cicmUR46ND6ggBB03bCnEG9OtGisxTo/TuYVRu3WP4KjoJs2LD5fwdwJqpgtHl
yVsk45Y1Hfo+7M6lAuR8rzCi6kHHNb0HyBmZjysHWZsn79ZM+sQnLpgaYgQGRbKV
DZWlbw7g7QKBgQCl1u+98UGXAP1jFutwbPsx40IVszP4y5ypCe0gqgon3UiY/G+1
zTLp79GGe/SjI2VpQ7AlW7TI2A0bXXvDSDi3/5Dfya9ULnFXv9yfvH1QwWToySpW
Kvd1gYSoiX84/WCtjZOr0e0HmLIb0vw0hqZA4szJSqoxQgvF22EfIWaIaQKBgQCf
34+OmMYw8fEvSCPxDxVvOwW2i7pvV14hFEDYIeZKW2W1HWBhVMzBfFB5SE8yaCQy
pRfOzj9aKOCm2FjjiErVNpkQoi6jGtLvScnhZAt/lr2TXTrl8OwVkPrIaN0bG/AS
aUYxmBPCpXu3UjhfQiWqFq/mFyzlqlgvuCc9g95HPQKBgAscKP8mLxdKwOgX8yFW
GcZ0izY/30012ajdHY+/QK5lsMoxTnn0skdS+spLxaS5ZEO4qvPVb8RAoCkWMMal
2pOhmquJQVDPDLuZHdrIiKiDM20dy9sMfHygWcZjQ4WSxf/J7T9canLZIXFhHAZT
3wc9h4G8BBCtWN2TN/LsGZdB
-----END PRIVATE KEY-----"#;

    fn keys(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    fn hex(value: &[u8]) -> String {
        value.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn credential_store(
        suffix: &str,
        scopes: &[&str],
        expires_at_ms: Option<i64>,
        revoked_at_ms: Option<i64>,
    ) -> (CredentialStore, String) {
        let root = std::env::temp_dir().join(format!(
            "coop-credential-test-{suffix}-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir_all(&root).expect("create fixture directory");
        let pepper = [0x5a_u8; 32];
        let key = format!("coop_key-{suffix}_{}", "a".repeat(43));
        let digest = credential_digest(&pepper, key.as_bytes());
        let pepper_path = root.join("pepper");
        let credentials_path = root.join("credentials.json");
        std::fs::write(&pepper_path, format!("{}\n", hex(&pepper))).expect("write pepper");
        std::fs::write(
            &credentials_path,
            serde_json::json!({
                "version": 1,
                "credentials": [{
                    "key_id": format!("key-{suffix}"),
                    "tenant_id": "tenant-a",
                    "principal_id": "agent-a",
                    "digest_hmac_sha256": hex(&digest),
                    "scopes": scopes,
                    "created_at_ms": 1,
                    "expires_at_ms": expires_at_ms,
                    "revoked_at_ms": revoked_at_ms
                }]
            })
            .to_string(),
        )
        .expect("write credentials");
        let store = CredentialStore::load(&credentials_path, &pepper_path, false)
            .expect("load credential fixture");
        (store, key)
    }

    #[test]
    fn jwt_algorithm_family_maps_known_algorithms() {
        use Algorithm::*;
        let cases = [
            (RS256, Some(JwtKeyFamily::Rsa)),
            (RS384, Some(JwtKeyFamily::Rsa)),
            (RS512, Some(JwtKeyFamily::Rsa)),
            (PS256, Some(JwtKeyFamily::Rsa)),
            (PS384, Some(JwtKeyFamily::Rsa)),
            (PS512, Some(JwtKeyFamily::Rsa)),
            (ES256, Some(JwtKeyFamily::Ec)),
            (ES384, Some(JwtKeyFamily::Ec)),
            (EdDSA, Some(JwtKeyFamily::Ed)),
            (HS256, None),
            (HS384, None),
            (HS512, None),
        ];
        for (algorithm, expected) in cases {
            assert_eq!(jwt_algorithm_family(algorithm), expected, "{algorithm:?}");
        }
    }

    #[test]
    fn legacy_authentication_is_exact_and_has_full_scopes() {
        let configured = keys(&[("s3cr3t", "acme")]);
        let auth = authenticate_legacy(&configured, "s3cr3t").expect("valid key");
        assert_eq!(auth.tenant_id, "acme");
        assert_eq!(auth.principal_id, "legacy:acme");
        assert_eq!(auth.scopes, ScopeSet::all());
        for bad in ["", "s", "s3cr3", "s3cr3tx", "x s3cr3t", "S3CR3T"] {
            assert!(authenticate_legacy(&configured, bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn indexed_hmac_credential_authenticates_without_retaining_secret() {
        let (store, key) = credential_store(
            "active",
            &["jobs:submit", "jobs:read"],
            Some(i64::MAX),
            None,
        );
        let rendered = format!("{store:?}");
        assert!(!rendered.contains(&key));
        assert!(rendered.contains("redacted"));
        let auth = store.authenticate(&key, 10).expect("valid credential");
        assert_eq!(auth.tenant_id, "tenant-a");
        assert_eq!(auth.principal_id, "agent-a");
        assert_eq!(auth.credential_id.as_deref(), Some("key-active"));
        assert!(auth.has_scope(Scope::JobsSubmit));
        assert!(auth.has_scope(Scope::JobsRead));
        assert!(!auth.has_scope(Scope::JobsCancel));
        assert!(store.authenticate(&format!("{key}wrong"), 10).is_none());
        assert!(store
            .authenticate(&format!("coop_unknown-identifier_{}", "b".repeat(43)), 10)
            .is_none());
    }

    #[test]
    fn expired_and_revoked_credentials_fail_closed() {
        let (expired, expired_key) = credential_store("expired", &["jobs:read"], Some(20), None);
        assert!(expired.authenticate(&expired_key, 19).is_some());
        assert!(expired.authenticate(&expired_key, 20).is_none());

        let (revoked, revoked_key) = credential_store("revoked", &["jobs:read"], None, Some(20));
        let before_revocation = revoked.authenticate(&revoked_key, 19).unwrap();
        assert_eq!(before_revocation.expires_at_ms, Some(20));
        assert!(revoked.authenticate(&revoked_key, 20).is_none());
        let legacy = HashMap::from([(revoked_key.clone(), "legacy-tenant".to_string())]);
        assert!(
            authenticate_local(&revoked, &legacy, &revoked_key, 20).is_none(),
            "a structured credential must not bypass revocation through legacy fallback"
        );

        let (expiry_first, expiry_first_key) =
            credential_store("expiry-first", &["jobs:read"], Some(20), Some(30));
        assert_eq!(
            expiry_first
                .authenticate(&expiry_first_key, 19)
                .unwrap()
                .expires_at_ms,
            Some(20)
        );
        let (revocation_first, revocation_first_key) =
            credential_store("revocation-first", &["jobs:read"], Some(30), Some(20));
        assert_eq!(
            revocation_first
                .authenticate(&revocation_first_key, 19)
                .unwrap()
                .expires_at_ms,
            Some(20)
        );
    }

    #[test]
    fn stream_ticket_expiry_is_bounded_by_authority_end() {
        let issued_at_ms = 1_000;
        let ttl_end_ms = issued_at_ms + STREAM_TICKET_TTL_MS;
        assert_eq!(stream_ticket_expiry_ms(issued_at_ms, None), ttl_end_ms);
        assert_eq!(
            stream_ticket_expiry_ms(issued_at_ms, Some(ttl_end_ms + 1)),
            ttl_end_ms
        );
        assert_eq!(
            stream_ticket_expiry_ms(issued_at_ms, Some(issued_at_ms + 10)),
            issued_at_ms + 10
        );
        assert_eq!(
            stream_ticket_expiry_ms(issued_at_ms, Some(issued_at_ms)),
            issued_at_ms
        );
    }

    #[test]
    fn credentials_file_rejects_unknown_scopes_duplicate_ids_and_secret_fields() {
        let root =
            std::env::temp_dir().join(format!("coop-credential-invalid-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&root).unwrap();
        let pepper_path = root.join("pepper");
        std::fs::write(&pepper_path, "11".repeat(32)).unwrap();
        let credentials_path = root.join("credentials.json");
        for credentials in [
            serde_json::json!([{
                "key_id":"a", "tenant_id":"t", "principal_id":"p",
                "digest_hmac_sha256":"22".repeat(32), "scopes":["admin:*"],
                "created_at_ms":1
            }]),
            serde_json::json!([{
                "key_id":"a", "tenant_id":"t", "principal_id":"p",
                "digest_hmac_sha256":"22".repeat(32), "scopes":[],
                "created_at_ms":1
            }, {
                "key_id":"a", "tenant_id":"t", "principal_id":"p2",
                "digest_hmac_sha256":"33".repeat(32), "scopes":[],
                "created_at_ms":1
            }]),
            serde_json::json!([{
                "key_id":"a", "tenant_id":"t", "principal_id":"p",
                "digest_hmac_sha256":"22".repeat(32), "scopes":[],
                "created_at_ms":1, "secret":"must-never-be-stored"
            }]),
        ] {
            std::fs::write(
                &credentials_path,
                serde_json::json!({"version":1,"credentials":credentials}).to_string(),
            )
            .unwrap();
            assert!(CredentialStore::load(&credentials_path, &pepper_path, false).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn production_credential_files_require_root_ownership_and_private_modes() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "coop-credential-permissions-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let pepper_path = root.join("pepper");
        let credentials_path = root.join("credentials.json");
        std::fs::write(&pepper_path, "11".repeat(32)).unwrap();
        std::fs::write(
            &credentials_path,
            serde_json::json!({
                "version":1,
                "credentials":[{
                    "key_id":"a", "tenant_id":"t", "principal_id":"p",
                    "digest_hmac_sha256":"22".repeat(32), "scopes":["jobs:read"],
                    "created_at_ms":1
                }]
            })
            .to_string(),
        )
        .unwrap();
        std::fs::set_permissions(&credentials_path, std::fs::Permissions::from_mode(0o644))
            .unwrap();
        std::fs::set_permissions(&pepper_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(CredentialStore::load(&credentials_path, &pepper_path, true).is_err());

        std::fs::set_permissions(&credentials_path, std::fs::Permissions::from_mode(0o600))
            .unwrap();
        assert!(
            CredentialStore::load(&credentials_path, &pepper_path, true).is_err(),
            "a private leaf below a shared temporary ancestor is still unsafe"
        );
    }

    #[test]
    fn scope_set_rejects_unknown_names_and_has_stable_order() {
        let scopes =
            ScopeSet::from_names(&["metrics:read".to_string(), "jobs:submit".to_string()]).unwrap();
        assert_eq!(scopes.names(), ["jobs:submit", "metrics:read"]);
        assert!(ScopeSet::from_names(&["jobs:*".to_string()]).is_err());
    }

    #[test]
    fn malformed_bearer_headers_are_not_accepted() {
        for value in [
            "Basic abc",
            "Bearer",
            "Bearer ",
            "Bearer  two",
            "Bearer a\tb",
        ] {
            let request = Request::builder()
                .header(header::AUTHORIZATION, value)
                .body(axum::body::Body::empty())
                .unwrap();
            assert!(matches!(extract_bearer(&request), Bearer::Malformed));
        }
    }

    fn jwt_config() -> JwtConfig {
        JwtConfig::parse(
            "https://issuer.example",
            "https://coop.example",
            "https://issuer.example/jwks.json",
            "tenant_id",
            "external-a=tenant-a",
            "RS256",
            300,
            3600,
        )
        .unwrap()
    }

    fn jwt_material() -> (JwtConfig, HashMap<String, CachedJwtKey>, EncodingKey) {
        let encoding = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY.as_bytes()).unwrap();
        let jwk: Jwk = serde_json::from_value(serde_json::json!({
            "kty":"RSA",
            "n":"yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKXxJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQ",
            "e":"AQAB",
            "kid":"test-key",
            "alg":"RS256",
            "use":"sig"
        }))
        .unwrap();
        let jwks = serde_json::to_vec(&serde_json::json!({"keys":[jwk]})).unwrap();
        let config = jwt_config();
        let keys = parse_jwks(&jwks, &config.algorithms).unwrap();
        (config, keys, encoding)
    }

    fn jwt_fixture() -> (JwtVerifier, EncodingKey) {
        let (config, keys, encoding) = jwt_material();
        let jwks = Arc::new(StaticJwksSource { keys: keys.clone() });
        (
            JwtVerifier {
                config,
                source: jwks,
                cache: RwLock::new(JwksCache {
                    keys,
                    valid_until: Instant::now() + Duration::from_secs(3600),
                    last_refresh_attempt: Some(Instant::now()),
                }),
                refresh_lock: Mutex::new(()),
            },
            encoding,
        )
    }

    fn valid_claims() -> Value {
        let now = now_seconds();
        serde_json::json!({
            "iss": "https://issuer.example",
            "sub": "agent-subject",
            "aud": "https://coop.example",
            "exp": now + 300,
            "iat": now,
            "jti": "token-id",
            "client_id": "agent-client",
            "scope": "jobs:submit jobs:read",
            "tenant_id": "external-a"
        })
    }

    fn sign_claims(
        encoding: &EncodingKey,
        claims: &Value,
        mutate: impl FnOnce(&mut Header),
    ) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".to_string());
        header.kid = Some("test-key".to_string());
        mutate(&mut header);
        encode(&header, claims, encoding).unwrap()
    }

    struct BlockingJwksSource {
        keys: HashMap<String, CachedJwtKey>,
        calls: AtomicUsize,
        entered: Semaphore,
        release: Semaphore,
    }

    impl BlockingJwksSource {
        fn new(keys: HashMap<String, CachedJwtKey>) -> Self {
            Self {
                keys,
                calls: AtomicUsize::new(0),
                entered: Semaphore::new(0),
                release: Semaphore::new(0),
            }
        }

        async fn wait_until_entered(&self) {
            self.entered.acquire().await.unwrap().forget();
        }

        fn release_one(&self) {
            self.release.add_permits(1);
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl JwksSource for BlockingJwksSource {
        fn fetch(&self) -> JwksFuture<'_> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.entered.add_permits(1);
                self.release.acquire().await.unwrap().forget();
                Ok(self.keys.clone())
            })
        }
    }

    fn verifier_with_source(
        config: JwtConfig,
        keys: HashMap<String, CachedJwtKey>,
        source: Arc<dyn JwksSource>,
        last_refresh_attempt: Option<Instant>,
    ) -> Arc<JwtVerifier> {
        Arc::new(JwtVerifier {
            config,
            source,
            cache: RwLock::new(JwksCache {
                keys,
                valid_until: Instant::now() + Duration::from_secs(3600),
                last_refresh_attempt,
            }),
            refresh_lock: Mutex::new(()),
        })
    }

    fn token_with_kid(encoding: &EncodingKey, kid: &str) -> String {
        sign_claims(encoding, &valid_claims(), |header| {
            header.kid = Some(kid.to_string());
        })
    }

    #[tokio::test]
    async fn cached_valid_token_bypasses_a_blocked_unknown_kid_refresh() {
        let (config, keys, encoding) = jwt_material();
        let source = Arc::new(BlockingJwksSource::new(keys.clone()));
        let verifier = verifier_with_source(
            config,
            keys,
            source.clone(),
            Some(Instant::now() - JWKS_UNKNOWN_KID_REFRESH_COOLDOWN - Duration::from_secs(1)),
        );
        let unknown = token_with_kid(&encoding, "unknown-key");
        let unknown_verifier = verifier.clone();
        let refresh = tokio::spawn(async move { unknown_verifier.authenticate(&unknown).await });
        tokio::time::timeout(Duration::from_secs(1), source.wait_until_entered())
            .await
            .expect("unknown kid starts one refresh");

        let valid = token_with_kid(&encoding, "test-key");
        let cached =
            tokio::time::timeout(Duration::from_millis(250), verifier.authenticate(&valid))
                .await
                .expect("cached verification must not wait for the refresh mutex");
        assert!(cached.is_ok());
        assert_eq!(source.calls(), 1);

        source.release_one();
        assert!(refresh.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn unknown_kid_cooldown_skips_fetch_and_returns_promptly() {
        let (config, keys, encoding) = jwt_material();
        let source = Arc::new(BlockingJwksSource::new(keys.clone()));
        let verifier = verifier_with_source(config, keys, source.clone(), Some(Instant::now()));
        let unknown = token_with_kid(&encoding, "unknown-key");
        let result =
            tokio::time::timeout(Duration::from_millis(250), verifier.authenticate(&unknown))
                .await
                .expect("cooldown rejection must not perform network I/O");
        assert!(result.is_err());
        assert_eq!(source.calls(), 0);
    }

    #[tokio::test]
    async fn concurrent_unknown_kids_singleflight_one_refresh() {
        let (config, keys, encoding) = jwt_material();
        let source = Arc::new(BlockingJwksSource::new(keys.clone()));
        let verifier = verifier_with_source(
            config,
            keys,
            source.clone(),
            Some(Instant::now() - JWKS_UNKNOWN_KID_REFRESH_COOLDOWN - Duration::from_secs(1)),
        );
        let unknown = token_with_kid(&encoding, "unknown-key");
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let verifier = verifier.clone();
            let token = unknown.clone();
            tasks.push(tokio::spawn(
                async move { verifier.authenticate(&token).await },
            ));
        }
        tokio::time::timeout(Duration::from_secs(1), source.wait_until_entered())
            .await
            .expect("one contender begins the refresh");
        assert_eq!(source.calls(), 1);
        source.release_one();
        let results = tokio::time::timeout(Duration::from_secs(2), async {
            futures_util::future::join_all(tasks).await
        })
        .await
        .expect("all cooldown followers complete without another fetch");
        assert!(results.into_iter().all(|result| result.unwrap().is_err()));
        assert_eq!(source.calls(), 1);
    }

    #[tokio::test]
    async fn strict_rfc9068_jwt_authenticates_and_maps_tenant_scopes_and_principal() {
        let (verifier, encoding) = jwt_fixture();
        let token = sign_claims(&encoding, &valid_claims(), |_| {});
        let auth = verifier.authenticate(&token).await.unwrap();
        assert_eq!(auth.tenant_id, "tenant-a");
        assert!(auth.principal_id.starts_with("oidc:"));
        assert_eq!(auth.method, AuthMethod::Jwt);
        assert!(auth.has_scope(Scope::JobsSubmit));
        assert!(auth.has_scope(Scope::JobsRead));
        assert!(!auth.has_scope(Scope::JobsCancel));
        assert!(auth.expires_at_ms.is_some());
    }

    #[tokio::test]
    async fn jwt_rejects_wrong_type_issuer_audience_expiry_age_tenant_and_scope() {
        let (verifier, encoding) = jwt_fixture();
        let now = now_seconds();
        let cases = [
            ("typ", serde_json::json!({})),
            ("issuer", serde_json::json!({"iss":"https://evil.example"})),
            (
                "audience",
                serde_json::json!({"aud":"https://other.example"}),
            ),
            (
                "expired",
                serde_json::json!({"exp":now - 61, "iat":now - 361}),
            ),
            ("exp-type", serde_json::json!({"exp":"not-a-number"})),
            ("nbf-type", serde_json::json!({"nbf":"not-a-number"})),
            ("iat-type", serde_json::json!({"iat":"not-a-number"})),
            ("age", serde_json::json!({"iat":now - 4000, "exp":now + 10})),
            ("tenant", serde_json::json!({"tenant_id":"unknown"})),
            ("scope", serde_json::json!({"scope":"jobs:read admin:*"})),
        ];
        for (name, changes) in cases {
            let mut claims = valid_claims();
            if let (Some(target), Some(changes)) = (claims.as_object_mut(), changes.as_object()) {
                target.extend(changes.clone());
            }
            let token = sign_claims(&encoding, &claims, |header| {
                if name == "typ" {
                    header.typ = Some("JWT".to_string());
                }
            });
            assert!(
                verifier.authenticate(&token).await.is_err(),
                "accepted {name}"
            );
        }
    }

    #[tokio::test]
    async fn jwt_rejects_missing_profile_claims_unknown_kid_and_token_supplied_key_urls() {
        let (verifier, encoding) = jwt_fixture();
        for claim in ["sub", "client_id", "iat", "jti", "scope", "tenant_id"] {
            let mut claims = valid_claims();
            claims.as_object_mut().unwrap().remove(claim);
            let token = sign_claims(&encoding, &claims, |_| {});
            assert!(
                verifier.authenticate(&token).await.is_err(),
                "accepted missing {claim}"
            );
        }

        let unknown_kid = sign_claims(&encoding, &valid_claims(), |header| {
            header.kid = Some("unknown-key".to_string());
        });
        assert!(verifier.authenticate(&unknown_kid).await.is_err());

        for header_name in ["jku", "x5u"] {
            let token = sign_claims(&encoding, &valid_claims(), |header| match header_name {
                "jku" => header.jku = Some("https://evil.example/jwks".to_string()),
                _ => header.x5u = Some("https://evil.example/key".to_string()),
            });
            assert!(
                verifier.authenticate(&token).await.is_err(),
                "accepted {header_name}"
            );
        }

        let critical_header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "typ":"at+jwt", "alg":"RS256", "kid":"test-key", "crit":["custom"]
            }))
            .unwrap(),
        );
        let critical = format!("{critical_header}.e30.invalid");
        assert!(verifier.authenticate(&critical).await.is_err());
    }

    #[tokio::test]
    async fn jwt_flows_through_http_auth_scope_and_no_store_layers() {
        let (verifier, encoding) = jwt_fixture();
        let mut claims = valid_claims();
        claims["scope"] = Value::String("service:read".to_string());
        let token = sign_claims(&encoding, &claims, |_| {});
        let db = std::env::temp_dir().join(format!("coop-jwt-http-{}.db", uuid::Uuid::now_v7()));
        let jobs = std::env::temp_dir().join(format!("coop-jwt-jobs-{}", uuid::Uuid::now_v7()));
        let mut config = crate::config::Config::from_sources(&|_| None, false).unwrap();
        config.sandbox = "off".to_string();
        config.jobs_root = jobs.to_string_lossy().into_owned();
        config.db_path = db.to_string_lossy().into_owned();
        let mut configured_state = config.clone();
        configured_state.jwt = Some(jwt_config());
        let store = Arc::new(
            coop_store::Store::open_with_limits(&db, config.storage_limits())
                .await
                .unwrap(),
        );
        let (unused, mut state, _queue_rx) = crate::build_app(
            config,
            store,
            "127.0.0.1:0".parse().expect("loopback test address"),
        )
        .await
        .unwrap();
        drop(unused);
        state.cfg = Arc::new(configured_state);
        state.jwt_verifier = Some(Arc::new(verifier));
        let app = crate::routes::router(state);

        let metadata = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/.well-known/oauth-protected-resource")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(metadata.status(), StatusCode::OK);
        let metadata = axum::body::to_bytes(metadata.into_body(), 8192)
            .await
            .unwrap();
        let metadata: Value = serde_json::from_slice(&metadata).unwrap();
        assert_eq!(metadata["resource"], "https://coop.example");
        assert_eq!(
            metadata["authorization_servers"][0],
            "https://issuer.example"
        );
        assert_eq!(
            metadata["bearer_methods_supported"],
            serde_json::json!(["header"])
        );

        let response = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/v1/whoami")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let body = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["tenant"], "tenant-a");
        assert_eq!(body["auth_method"], "jwt");
        assert_eq!(body["scopes"], serde_json::json!(["service:read"]));

        claims["scope"] = Value::String("jobs:read".to_string());
        let read_only = sign_claims(&encoding, &claims, |_| {});
        let denied = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/v1/whoami")
                    .header(header::AUTHORIZATION, format!("Bearer {read_only}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        assert!(denied
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("service:read"));
    }

    #[test]
    fn oidc_configuration_rejects_partial_insecure_symmetric_and_ambiguous_values() {
        for (issuer, audience, jwks, claim, map, algorithms) in [
            (
                "http://issuer.example",
                "https://coop.example",
                "https://issuer.example/jwks",
                "tenant_id",
                "a=t",
                "RS256",
            ),
            (
                "https://issuer.example",
                "http://coop.example",
                "https://issuer.example/jwks",
                "tenant_id",
                "a=t",
                "RS256",
            ),
            (
                "https://issuer.example",
                "https://coop.example",
                "http://issuer.example/jwks",
                "tenant_id",
                "a=t",
                "RS256",
            ),
            (
                "https://issuer.example",
                "https://coop.example",
                "https://issuer.example/jwks?token=must-not-enter-config",
                "tenant_id",
                "a=t",
                "RS256",
            ),
            (
                "https://issuer.example",
                "https://coop.example",
                "https://issuer.example/jwks",
                "sub",
                "a=t",
                "RS256",
            ),
            (
                "https://issuer.example",
                "https://coop.example",
                "https://issuer.example/jwks",
                "tenant_id",
                "a=t,a=other",
                "RS256",
            ),
            (
                "https://issuer.example",
                "https://coop.example",
                "https://issuer.example/jwks",
                "tenant_id",
                "a=t",
                "HS256",
            ),
        ] {
            assert!(
                JwtConfig::parse(issuer, audience, jwks, claim, map, algorithms, 300, 3600)
                    .is_err()
            );
        }
        let secret_query = JwtConfig::parse(
            "https://issuer.example",
            "https://coop.example",
            "https://issuer.example/jwks?token=must-not-enter-debug",
            "tenant_id",
            "a=t",
            "RS256",
            300,
            3600,
        )
        .unwrap_err();
        assert!(!secret_query.contains("must-not-enter-debug"));
    }
}
