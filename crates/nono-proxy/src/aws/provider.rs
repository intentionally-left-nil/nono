//! AWS credential provider construction.
//!
//! Builds `SharedCredentialsProvider` instances from a profile name (or the
//! default credential chain) and caches them by profile key so multiple routes
//! using the same profile share one identity cache and one set of refreshes.

use aws_config::BehaviorVersion;
use aws_config::profile::ProfileFileCredentialsProvider;
use aws_credential_types::provider::SharedCredentialsProvider;
use std::collections::HashMap;
use tracing::debug;

/// Sentinel key used when no profile is configured.
pub const DEFAULT_PROFILE_KEY: &str = "<default>";

/// Build (or retrieve from the cache) a `SharedCredentialsProvider` for the
/// given profile.
///
/// - `Some(name)`: build a `ProfileFileCredentialsProvider` for the named
///   profile. This reads **only** `~/.aws/config` and `~/.aws/credentials`
///   for the named profile and does **not** consult environment variables.
///   This is intentional: when the proxy is running inside a session that
///   injects dummy `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` env vars for
///   the sandboxed child (to prevent it from using real credentials directly),
///   the named-profile path must bypass those env vars so the proxy itself can
///   sign with the real profile credentials.
/// - `None`: build the full default credential chain (env vars → `AWS_PROFILE`
///   → default profile → web identity → ECS → IMDS → SSO). Use this only when
///   no profile name is explicitly configured.
///
/// The cache is keyed on `profile.unwrap_or(DEFAULT_PROFILE_KEY)` to allow
/// reuse across routes that share an identity.
///
/// # Errors
///
/// Returns an error string (suitable for `warn!` + skip) on any construction
/// failure. Does not abort the proxy.
pub async fn get_or_build_provider(
    profile: Option<&str>,
    cache: &mut HashMap<String, SharedCredentialsProvider>,
) -> Result<SharedCredentialsProvider, String> {
    let key = profile.unwrap_or(DEFAULT_PROFILE_KEY).to_string();

    if let Some(p) = cache.get(&key) {
        debug!("aws::provider: cache hit for profile_key='{}'", key);
        return Ok(p.clone());
    }

    debug!(
        "aws::provider: cache miss for profile_key='{}'; building provider",
        key
    );
    let provider = build_provider(profile).await?;
    debug!(
        "aws::provider: provider built successfully for profile_key='{}'",
        key
    );
    cache.insert(key, provider.clone());
    Ok(provider)
}

/// Build a fresh `SharedCredentialsProvider` without caching.
async fn build_provider(profile: Option<&str>) -> Result<SharedCredentialsProvider, String> {
    // Pin the behavior version to avoid silent breaking changes from
    // BehaviorVersion::latest().
    let behavior = BehaviorVersion::v2026_01_12();

    let provider = match profile {
        Some(name) => {
            // Use ProfileFileCredentialsProvider directly so that environment
            // variables (including dummy AWS_ACCESS_KEY_ID values that may be
            // injected into the session for the sandboxed child) are NOT
            // consulted. The default chain (from_env()) checks env vars first,
            // which causes it to pick up the dummy credentials instead of the
            // real profile from ~/.aws/config.
            debug!(
                "aws::provider: building ProfileFileCredentialsProvider for profile '{}'",
                name
            );
            let inner = ProfileFileCredentialsProvider::builder()
                .profile_name(name)
                .build();
            SharedCredentialsProvider::new(inner)
        }
        None => {
            debug!(
                "aws::provider: loading default credential chain \
                 (env vars → AWS_PROFILE → default profile → web identity → ECS → IMDS → SSO)"
            );
            let sdk_config = aws_config::from_env()
                .behavior_version(behavior)
                .load()
                .await;
            sdk_config
                .credentials_provider()
                .ok_or_else(|| {
                    "default AWS credential chain yielded no credentials provider — \
                     configure AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY or an AWS profile"
                        .to_string()
                })?
                .clone()
        }
    };

    Ok(provider)
}
