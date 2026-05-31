//! Region and service resolution for AWS SigV4 routes.
//!
//! Resolution order for both `region` and `service`:
//! 1. Explicit override in `aws_auth`.
//! 2. Auto-detection from the upstream hostname.
//! 3. Startup error (proxy will warn-and-skip the route).

use super::endpoints;

/// Resolve the SigV4 signing region for a route.
///
/// # Parameters
/// - `explicit`: the `aws_auth.region` override (if set by the user).
/// - `upstream_host`: the hostname from the route's `upstream` URL.
///
/// # Errors
///
/// Returns an error string (for `warn!` + skip) when neither the override nor
/// the host parse yields a region.
pub fn resolve_region(explicit: Option<&str>, upstream_host: &str) -> Result<String, String> {
    if let Some(r) = explicit {
        if r.is_empty() {
            return Err(
                "aws_auth.region is set but empty — provide a region like \"us-east-1\" \
                        or remove the field to use auto-detection"
                    .to_string(),
            );
        }
        return Ok(r.to_string());
    }

    endpoints::lookup_region(upstream_host).ok_or_else(|| {
        format!(
            "could not auto-detect AWS region from upstream host '{}'; \
             set aws_auth.region explicitly (e.g., \"us-east-1\")",
            upstream_host
        )
    })
}

/// Resolve the SigV4 service name for a route.
///
/// # Parameters
/// - `explicit`: the `aws_auth.service` override (if set by the user).
/// - `upstream_host`: the hostname from the route's `upstream` URL.
///
/// # Errors
///
/// Returns an error string (for `warn!` + skip) when neither the override nor
/// the table lookup yields a service name.
pub fn resolve_service(explicit: Option<&str>, upstream_host: &str) -> Result<String, String> {
    if let Some(s) = explicit {
        if s.is_empty() {
            return Err(
                "aws_auth.service is set but empty — provide a service name like \
                        \"bedrock\" or \"s3\", or remove the field to use auto-detection"
                    .to_string(),
            );
        }
        return Ok(s.to_string());
    }

    endpoints::lookup_service(upstream_host)
        .map(|s| s.to_string())
        .ok_or_else(|| {
            format!(
                "could not auto-detect AWS service name from upstream host '{}'; \
                 set aws_auth.service explicitly (e.g., \"bedrock\", \"s3\")",
                upstream_host
            )
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn explicit_region_wins() {
        let r = resolve_region(
            Some("eu-central-1"),
            "bedrock-runtime.us-east-1.amazonaws.com",
        );
        assert_eq!(r.unwrap(), "eu-central-1");
    }

    #[test]
    fn region_parsed_from_host() {
        let r = resolve_region(None, "bedrock-runtime.us-east-1.amazonaws.com");
        assert_eq!(r.unwrap(), "us-east-1");
    }

    #[test]
    fn region_auto_detect_fails_for_global_service() {
        // IAM has no region in the host; must supply explicit override.
        let r = resolve_region(None, "iam.amazonaws.com");
        assert!(r.is_err(), "expected error for global IAM host");
        let msg = r.unwrap_err();
        assert!(
            msg.contains("aws_auth.region"),
            "error should suggest aws_auth.region, got: {}",
            msg
        );
    }

    #[test]
    fn region_empty_override_is_error() {
        let r = resolve_region(Some(""), "bedrock-runtime.us-east-1.amazonaws.com");
        assert!(r.is_err());
    }

    #[test]
    fn explicit_service_wins() {
        let s = resolve_service(
            Some("my-service"),
            "bedrock-runtime.us-east-1.amazonaws.com",
        );
        assert_eq!(s.unwrap(), "my-service");
    }

    #[test]
    fn service_looked_up_from_table() {
        let s = resolve_service(None, "bedrock-runtime.us-east-1.amazonaws.com");
        assert_eq!(s.unwrap(), "bedrock");
    }

    #[test]
    fn service_unknown_host_returns_error() {
        let s = resolve_service(None, "unknownsvc.us-east-1.amazonaws.com");
        assert!(s.is_err());
        let msg = s.unwrap_err();
        assert!(
            msg.contains("aws_auth.service"),
            "error should suggest aws_auth.service, got: {}",
            msg
        );
    }

    #[test]
    fn service_empty_override_is_error() {
        let s = resolve_service(Some(""), "bedrock-runtime.us-east-1.amazonaws.com");
        assert!(s.is_err());
    }
}
