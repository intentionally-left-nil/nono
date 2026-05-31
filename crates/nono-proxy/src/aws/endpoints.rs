//! Host-to-SigV4-service mapping table.
//!
//! Maps the first dotted segment of an `*.amazonaws.com` hostname to the
//! canonical SigV4 service name AWS expects. This mapping is irregular
//! (e.g., `bedrock-runtime` → `bedrock`; `email` → `ses`), so it cannot
//! be derived algorithmically — a hand-curated table is the correct approach.
//!
//! Adding a new service is a one-line change here plus one test row. Users
//! on unlisted services can supply an explicit `aws_auth.service` override.

/// Mapping from the first dotted segment of an AWS hostname to the SigV4
/// service name. Order matters: first match wins.
///
/// To add a new service: add a `(&"host-prefix", &"sigv4-service-name")` row
/// and a corresponding test in `tests::lookup_service_table`.
pub static AWS_HOST_TO_SERVICE: &[(&str, &str)] = &[
    // Bedrock — the primary use case. Multiple host prefixes, one service name.
    ("bedrock", "bedrock"),
    ("bedrock-runtime", "bedrock"),
    ("bedrock-agent", "bedrock"),
    ("bedrock-agent-runtime", "bedrock"),
    // Core developer services
    ("dynamodb", "dynamodb"),
    ("s3", "s3"),
    ("lambda", "lambda"),
    ("sqs", "sqs"),
    ("sns", "sns"),
    ("logs", "logs"), // CloudWatch Logs
    // API Gateway
    ("execute-api", "execute-api"),
    // Identity / signing
    ("sts", "sts"),
    ("iam", "iam"),
    // Email
    ("email", "ses"),
    ("ses", "ses"),
];

/// Look up the SigV4 service name for an AWS hostname.
///
/// Matches on the first dotted segment of `host` (e.g.,
/// `bedrock-runtime.us-east-1.amazonaws.com` → first segment `bedrock-runtime`).
/// Returns `None` if the host doesn't match any known prefix.
#[must_use]
pub fn lookup_service(host: &str) -> Option<&'static str> {
    let prefix = host.split('.').next()?;
    AWS_HOST_TO_SERVICE
        .iter()
        .find(|(p, _)| *p == prefix)
        .map(|(_, svc)| *svc)
}

/// Extract the AWS region from an AWS hostname.
///
/// Parses the second dotted segment of `<service>.<region>.amazonaws.com`
/// and validates it looks like an AWS region (lowercase, hyphens, digits only).
/// Returns `None` if the host doesn't match the expected shape.
#[must_use]
pub fn lookup_region(host: &str) -> Option<String> {
    let mut parts = host.split('.');
    // Skip first segment (service prefix)
    parts.next()?;
    let region = parts.next()?;
    // Validate: must look like a region (e.g., "us-east-1", "eu-west-2").
    // Accepts lowercase ASCII letters, digits, and hyphens only.
    if region.is_empty()
        || !region
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return None;
    }
    // Must contain at least one hyphen (all real regions have "us-east-1" shape)
    // and must end in a digit (the AZ index).
    if !region.contains('-') || !region.ends_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    Some(region.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Every row in the table must have a corresponding test entry here.
    /// Adding a new service row forces adding a test row.
    #[test]
    fn lookup_service_table() {
        let cases = [
            ("bedrock.us-east-1.amazonaws.com", "bedrock"),
            ("bedrock-runtime.us-east-1.amazonaws.com", "bedrock"),
            ("bedrock-agent.us-east-1.amazonaws.com", "bedrock"),
            ("bedrock-agent-runtime.us-east-1.amazonaws.com", "bedrock"),
            ("dynamodb.us-east-1.amazonaws.com", "dynamodb"),
            ("s3.us-east-1.amazonaws.com", "s3"),
            ("lambda.us-east-1.amazonaws.com", "lambda"),
            ("sqs.us-east-1.amazonaws.com", "sqs"),
            ("sns.us-east-1.amazonaws.com", "sns"),
            ("logs.us-east-1.amazonaws.com", "logs"),
            ("execute-api.us-east-1.amazonaws.com", "execute-api"),
            ("sts.amazonaws.com", "sts"),
            ("iam.amazonaws.com", "iam"),
            ("email.us-east-1.amazonaws.com", "ses"),
            ("ses.us-east-1.amazonaws.com", "ses"),
        ];
        for (host, expected_svc) in cases {
            let got = lookup_service(host);
            assert_eq!(
                got,
                Some(expected_svc),
                "lookup_service({host:?}) expected Some({expected_svc:?}), got {got:?}"
            );
        }
    }

    #[test]
    fn lookup_service_unknown_host_returns_none() {
        assert_eq!(lookup_service("unknownsvc.us-east-1.amazonaws.com"), None);
        assert_eq!(lookup_service(""), None);
        assert_eq!(lookup_service("localhost"), None);
    }

    #[test]
    fn lookup_region_standard_hosts() {
        assert_eq!(
            lookup_region("bedrock-runtime.us-east-1.amazonaws.com"),
            Some("us-east-1".to_string())
        );
        assert_eq!(
            lookup_region("s3.eu-west-2.amazonaws.com"),
            Some("eu-west-2".to_string())
        );
        assert_eq!(
            lookup_region("lambda.ap-southeast-1.amazonaws.com"),
            Some("ap-southeast-1".to_string())
        );
    }

    #[test]
    fn lookup_region_global_services_return_none() {
        // Global services like IAM don't have a region in the hostname.
        // "amazonaws" doesn't match the region shape (no trailing digit).
        assert_eq!(lookup_region("iam.amazonaws.com"), None);
        assert_eq!(lookup_region("sts.amazonaws.com"), None);
    }

    #[test]
    fn lookup_region_invalid_shape() {
        assert_eq!(lookup_region(""), None);
        assert_eq!(lookup_region("localhost"), None);
        // "UPPERCASE" is not a valid region (no uppercase in real regions)
        assert_eq!(lookup_region("s3.US-EAST-1.amazonaws.com"), None);
    }
}
