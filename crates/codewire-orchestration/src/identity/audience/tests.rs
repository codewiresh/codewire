use super::*;

fn canonical(input: &str) -> String {
    CanonicalAudience::parse(input)
        .unwrap_or_else(|error| panic!("{input:?}: {error}"))
        .to_string()
}

fn refused(input: &str) -> AudienceError {
    CanonicalAudience::parse(input).expect_err(input)
}

/// Codewire's own production domains, as `FRONTEND_URL`, `PREVIEW_BASE_DOMAIN`
/// and `CODEWIRE_IDENTITY_ISSUER_BASE` name them.
fn deployment() -> AudienceDenylist {
    AudienceDenylist::for_deployment(
        "https://codewire.sh",
        "cwpreview.sh",
        Some("https://identity.codewire.sh"),
    )
}

fn registered(input: &str) -> Result<String, AudienceError> {
    let audience = CanonicalAudience::parse(input)?;
    deployment().check(&audience)?;
    Ok(audience.to_string())
}

#[test]
fn the_spec_example_matches_its_registration() {
    // The journey's step 3: a resource in another spelling names the
    // registered `https://k8s.walk.example`.
    assert_eq!(
        canonical("HTTPS://K8S.WALK.EXAMPLE:443"),
        "https://k8s.walk.example"
    );
    assert_eq!(
        registered("https://k8s.walk.example").unwrap(),
        "https://k8s.walk.example"
    );
}

#[test]
fn the_scheme_and_host_are_lowercased_and_the_host_is_a_labels() {
    assert_eq!(
        canonical("hTTpS://Verifier.Example"),
        "https://verifier.example"
    );
    assert_eq!(
        canonical("https://Bücher.Example/x"),
        "https://xn--bcher-kva.example/x"
    );
    assert_eq!(
        canonical("https://xn--bcher-kva.example"),
        "https://xn--bcher-kva.example"
    );
}

#[test]
fn only_the_default_port_is_dropped() {
    assert_eq!(canonical("https://v.example:443/a"), "https://v.example/a");
    assert_eq!(
        canonical("https://v.example:8443/a"),
        "https://v.example:8443/a"
    );
    assert_eq!(canonical("https://v.example:0443"), "https://v.example");
    for input in [
        "https://v.example:",
        "https://v.example:0",
        "https://v.example:65536",
        "https://v.example:-1",
        "https://v.example:44a",
    ] {
        assert_eq!(refused(input), AudienceError::InvalidPort, "{input}");
    }
}

#[test]
fn the_path_is_kept_exactly_as_written() {
    for (input, expected) in [
        ("https://v.example", "https://v.example"),
        ("https://v.example/", "https://v.example/"),
        ("https://v.example/A/B/", "https://v.example/A/B/"),
        ("https://v.example/a/../b", "https://v.example/a/../b"),
        ("https://v.example/a%2Fb", "https://v.example/a%2Fb"),
        ("https://v.example//x", "https://v.example//x"),
        ("https://v.example/@:;=", "https://v.example/@:;="),
    ] {
        assert_eq!(canonical(input), expected, "{input}");
    }
    // Two spellings of a path are two audiences.
    assert_ne!(
        canonical("https://v.example"),
        canonical("https://v.example/")
    );
    for input in [
        "https://v.example/a b",
        "https://v.example/%",
        "https://v.example/%2",
        "https://v.example/%zz",
        "https://v.example/ä",
        "https://v.example/a\\b",
        "https://v.example/\n",
    ] {
        assert_eq!(refused(input), AudienceError::InvalidPath, "{input:?}");
    }
}

#[test]
fn each_form_rule_has_its_own_refusal() {
    for (input, error) in [
        ("", AudienceError::NotAbsolute),
        ("k8s.walk.example", AudienceError::NotAbsolute),
        ("sts.amazonaws.com", AudienceError::NotAbsolute),
        ("https:k8s.walk.example", AudienceError::NotAbsolute),
        ("1https://x.example", AudienceError::NotAbsolute),
        (" https://x.example", AudienceError::NotAbsolute),
        ("http://k8s.walk.example", AudienceError::NotHttps),
        ("api://AzureADTokenExchange", AudienceError::NotHttps),
        ("wss://x.example", AudienceError::NotHttps),
        ("https://user@x.example", AudienceError::Userinfo),
        ("https://user:pw@x.example/", AudienceError::Userinfo),
        ("https://k8s.walk.example/?a=1", AudienceError::Query),
        ("https://x.example?", AudienceError::Query),
        ("https://x.example/#top", AudienceError::Fragment),
        ("https://x.example#", AudienceError::Fragment),
        ("https://", AudienceError::InvalidHost),
        ("https:///path", AudienceError::InvalidHost),
        ("https://x.example./", AudienceError::InvalidHost),
        ("https://x..example", AudienceError::InvalidHost),
        ("https://.x.example", AudienceError::InvalidHost),
        ("https://x example", AudienceError::InvalidHost),
        ("https://[::1", AudienceError::InvalidHost),
        ("https://[::1]x", AudienceError::InvalidHost),
    ] {
        assert_eq!(refused(input), error, "{input:?}");
    }
    let long = format!("https://x.example/{}", "a".repeat(MAX_AUDIENCE_BYTES));
    assert_eq!(refused(&long), AudienceError::TooLong);
}

#[test]
fn registration_refuses_the_deployments_domains_and_every_host_under_them() {
    for (input, domain) in [
        ("https://codewire.sh", "codewire.sh"),
        ("https://api.codewire.sh", "codewire.sh"),
        ("https://x.codewire.sh/", "codewire.sh"),
        ("https://IDENTITY.CODEWIRE.SH/orgs/x", "codewire.sh"),
        ("https://cwpreview.sh", "cwpreview.sh"),
        ("https://app-1.org.cwpreview.sh:8443/", "cwpreview.sh"),
    ] {
        assert_eq!(
            registered(input),
            Err(AudienceError::DeploymentDomain(domain.to_owned())),
            "{input}"
        );
    }
    // A name that only ends in the same letters is another domain.
    for input in ["https://notcodewire.sh", "https://codewire.sh.example"] {
        assert!(registered(input).is_ok(), "{input}");
    }
}

#[test]
fn the_deployments_domains_come_from_its_configuration() {
    let denylist = AudienceDenylist::for_deployment(
        "https://App.Example.COM:8443/dashboard",
        "previews.example.net",
        Some("https://identity.example.org/base"),
    );
    assert_eq!(
        denylist.deployment_domains(),
        [
            "app.example.com",
            "identity.example.org",
            "previews.example.net"
        ]
    );
    // A local install's loopback dashboard and unset preview domain name no
    // domain.
    let local = AudienceDenylist::for_deployment("http://127.0.0.1:5173", "", None);
    assert!(local.deployment_domains().is_empty());
    let issuer_under_dashboard = AudienceDenylist::for_deployment(
        "https://codewire.sh",
        "cwpreview.sh",
        Some("https://identity.codewire.sh"),
    );
    assert_eq!(
        issuer_under_dashboard.deployment_domains(),
        ["codewire.sh", "cwpreview.sh", "identity.codewire.sh"]
    );
}

#[test]
fn registration_refuses_the_in_cluster_kubernetes_api() {
    for input in [
        "https://kubernetes",
        "https://kubernetes.default",
        "https://kubernetes.default.svc",
        "https://Kubernetes.Default.Svc:443/",
        "https://kubernetes.default.svc.cluster.local",
        "https://kubernetes.default.svc.example",
        "https://api.kubernetes.default.svc",
    ] {
        assert_eq!(
            registered(input),
            Err(AudienceError::InClusterKubernetes),
            "{input}"
        );
    }
    assert!(registered("https://kubernetes.example").is_ok());
}

#[test]
fn registration_refuses_ip_addresses_in_every_spelling() {
    for input in [
        "https://10.0.0.1",
        "https://169.254.169.254/latest",
        "https://127.0.0.1:8443",
        "https://[::1]",
        "https://[fe80::1]/",
        "https://[2001:db8::1]:443",
        "https://8.8.8.8",
        // What an HTTP client reads as 127.0.0.1 and 10.0.0.1.
        "https://2130706433",
        "https://0x7f.1",
        "https://10.1",
        "https://10.0.0.1.",
    ] {
        assert_eq!(registered(input), Err(AudienceError::IpAddress), "{input}");
    }
    assert_eq!(canonical("https://[0:0::1]:8443/"), "https://[::1]:8443/");
}

#[test]
fn registration_refuses_local_and_private_network_names() {
    for input in [
        "https://localhost",
        "https://LOCALHOST:8443",
        "https://api.localhost",
        "https://openbao.openbao.svc.cluster.local",
        "https://printer.local",
        "https://router.home.arpa",
        "https://vault.internal",
        "https://openbao",
    ] {
        assert_eq!(
            registered(input),
            Err(AudienceError::PrivateHost),
            "{input}"
        );
    }
    for input in [
        "https://k8s.walk.example",
        "https://vault.example.com:8200/v1/auth/jwt",
        "https://sts.amazonaws.com/",
        "https://localhost.example",
    ] {
        assert!(registered(input).is_ok(), "{input}");
    }
}

#[test]
fn a_refusal_names_the_rule_it_breaks() {
    for (input, words) in [
        ("http://k8s.walk.example", "https"),
        ("https://k8s.walk.example/?a=1", "query"),
        ("https://kubernetes.default.svc", "Kubernetes"),
        ("https://10.0.0.1", "IP address"),
        ("https://api.codewire.sh", "codewire.sh"),
        ("https://x.codewire.sh/", "deployment serves it"),
    ] {
        let error = registered(input).unwrap_err().to_string();
        assert!(error.contains(words), "{input}: {error}");
    }
}
