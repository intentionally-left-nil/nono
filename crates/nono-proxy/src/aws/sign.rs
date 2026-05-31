//! SigV4 signing for outbound AWS requests.
//!
//! Strips incoming AWS auth headers from the agent, resolves credentials via
//! the route's provider, and returns the signed headers to inject instead.
//!
//! The caller is responsible for:
//!   1. Stripping `Authorization` and all `x-amz-*` headers from the
//!      agent-supplied headers before calling this function.
//!   2. Injecting the returned headers into the outbound request.

use super::route::AwsRoute;
use aws_credential_types::provider::ProvideCredentials;
use aws_sigv4::http_request::{
    PayloadChecksumKind, PercentEncodingMode, SessionTokenMode, SignableBody, SignableRequest,
    SigningSettings, UriPathNormalizationMode, sign,
};
use aws_sigv4::sign::v4;
use std::time::SystemTime;
use tracing::debug;

/// Check if a header name should be stripped as an AWS header.
///
/// Strips `Authorization` (exact match, case-insensitive) and all headers
/// whose names start with `x-amz-` (case-insensitive).
#[must_use]
pub fn is_aws_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "authorization" || lower.starts_with("x-amz-")
}

/// Compute a fresh SigV4 signature and return the headers to inject.
///
/// # Parameters
/// - `route`: the resolved `AwsRoute` for this upstream.
/// - `method`: HTTP method (e.g., `"POST"`).
/// - `url`: full URL including scheme, host, path, and query string
///   (e.g., `"https://bedrock-runtime.us-east-1.amazonaws.com/model/.../invoke"`).
/// - `clean_headers`: the request headers with all `x-amz-*` and
///   `Authorization` headers already removed. These are passed to the signer
///   so they are included in the `SignedHeaders` list.
/// - `body`: the complete request body bytes.
///
/// # Returns
///
/// A `Vec<(String, String)>` of headers to add to the request:
/// `Authorization`, `X-Amz-Date`, `X-Amz-Content-Sha256`, and optionally
/// `X-Amz-Security-Token`. The caller injects these into the outbound request.
///
/// # Errors
///
/// Returns a human-readable error string on credential failure or signing
/// failure. The caller should map this to a 503 with
/// `ManagedCredentialUnavailable`.
pub async fn sign_request(
    route: &AwsRoute,
    method: &str,
    url: &str,
    clean_headers: &[(String, String)],
    body: &[u8],
) -> Result<Vec<(String, String)>, String> {
    // Resolve credentials from the provider.
    let credentials = route.provider.provide_credentials().await.map_err(|e| {
        format!(
            "AWS credential resolution failed for route '{}': {}",
            route.service, e
        )
    })?;

    // Log key prefix (never the full key) and session token presence for
    // diagnosis without leaking secrets.
    let key_id = credentials.access_key_id();
    let key_prefix = if key_id.len() >= 4 {
        &key_id[..4]
    } else {
        key_id
    };
    let has_session_token = credentials.session_token().is_some();
    debug!(
        "aws::sign: signing {} {} for service={} region={} \
         key_id_prefix={}... has_session_token={}",
        method, url, route.service, route.region, key_prefix, has_session_token
    );

    // Build the identity from the resolved credentials.
    // `From<Credentials> for Identity` is implemented in aws-credential-types.
    let identity = credentials.into();

    // Build signing settings.
    // - `XAmzSha256`: include X-Amz-Content-Sha256 header (required for S3,
    //   correct for all other services).
    // - `SessionTokenMode::Include`: include X-Amz-Security-Token in the
    //   canonical request when a session token is present (STS / IMDS / SSO).
    // - `PercentEncodingMode::Single`: standard single-encode mode.
    // - `UriPathNormalizationMode::Disabled`: required for S3 key correctness.
    let mut settings = SigningSettings::default();
    settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
    settings.session_token_mode = SessionTokenMode::Include;
    settings.percent_encoding_mode = PercentEncodingMode::Single;
    settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;

    // Build signing parameters. `v2025_01_17` is the pinned behavior version.
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region(&route.region)
        .name(&route.service)
        .time(SystemTime::now())
        .settings(settings)
        .build()
        .map_err(|e| format!("failed to build SigV4 signing params: {}", e))?
        .into();

    // Build the signable request. Headers are passed as `(&str, &str)` pairs.
    let header_pairs: Vec<(&str, &str)> = clean_headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let signable = SignableRequest::new(
        method,
        url,
        header_pairs.into_iter(),
        SignableBody::Bytes(body),
    )
    .map_err(|e| format!("failed to build signable request: {}", e))?;

    // Sign and extract the instructions.
    let (instructions, _signature) = sign(signable, &params)
        .map_err(|e| format!("SigV4 signing failed: {}", e))?
        .into_parts();

    // Collect the new headers to inject.
    let new_headers: Vec<(String, String)> = instructions
        .headers()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    debug!(
        "aws::sign: produced {} signing headers: {:?}",
        new_headers.len(),
        new_headers
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
    );

    Ok(new_headers)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn is_aws_header_matches_authorization() {
        assert!(is_aws_header("Authorization"));
        assert!(is_aws_header("authorization"));
        assert!(is_aws_header("AUTHORIZATION"));
    }

    #[test]
    fn is_aws_header_matches_x_amz_prefix() {
        assert!(is_aws_header("X-Amz-Date"));
        assert!(is_aws_header("x-amz-date"));
        assert!(is_aws_header("x-amz-content-sha256"));
        assert!(is_aws_header("X-Amz-Security-Token"));
    }

    #[test]
    fn is_aws_header_does_not_match_other_headers() {
        assert!(!is_aws_header("Content-Type"));
        assert!(!is_aws_header("Host"));
        assert!(!is_aws_header("Accept"));
        assert!(!is_aws_header("X-Custom-Header"));
    }
}
