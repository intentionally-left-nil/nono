//! `AwsRoute` — per-route AWS SigV4 state.
//!
//! Holds the resolved region, service, upstream URL, and `SharedCredentialsProvider`
//! for one SigV4-enabled route.

use aws_credential_types::provider::SharedCredentialsProvider;

/// A fully-resolved AWS SigV4 route entry.
///
/// Created at proxy startup from a `RouteConfig` with an `aws_auth` block.
/// Stored in `CredentialStore::aws_routes` keyed on the normalised route prefix.
pub struct AwsRoute {
    /// The upstream URL (e.g., `https://bedrock-runtime.us-east-1.amazonaws.com`).
    /// Used to extract `Host` when building the signable URL.
    pub upstream: String,

    /// SigV4 signing region (e.g., `"us-east-1"`).
    pub region: String,

    /// SigV4 service name (e.g., `"bedrock"`).
    pub service: String,

    /// The profile key used when building the provider.
    /// `"<default>"` when no profile was configured.
    /// Stored to support identity-sharing across routes that use the same profile.
    pub profile_key: String,

    /// Credential provider. Shared across routes with the same `profile_key`
    /// to avoid duplicate STS/SSO refreshes.
    pub provider: SharedCredentialsProvider,
}

impl std::fmt::Debug for AwsRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsRoute")
            .field("upstream", &self.upstream)
            .field("region", &self.region)
            .field("service", &self.service)
            .field("profile_key", &self.profile_key)
            .field("provider", &"[SharedCredentialsProvider]")
            .finish()
    }
}
