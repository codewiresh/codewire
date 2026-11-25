use super::*;

fn reserved() -> ReservedHosts {
    ReservedHosts::new([
        "openbao.sandbox.example.dev",
        "registry.example.dev",
        "*.preview.example.dev",
    ])
    .unwrap()
}

fn host(name: &str) -> BoundHost {
    BoundHost::parse(name, &reserved()).unwrap()
}

fn binding(hosts: &[&str], presentation: Presentation, prefix: Option<&str>) -> HostBinding {
    HostBinding::new(
        hosts.iter().map(|name| host(name)).collect(),
        presentation,
        prefix.map(|prefix| PlaceholderPrefix::parse(prefix).unwrap()),
    )
    .unwrap()
}

#[test]
fn a_public_name_is_bound_in_lowercase_with_or_without_its_port() {
    assert_eq!(host("API.Fancy.com").as_str(), "api.fancy.com");
    assert_eq!(host("api.fancy.com:443").as_str(), "api.fancy.com");
}

#[test]
fn hosts_that_are_not_one_exact_public_name_are_refused() {
    let reserved = reserved();
    let refused = |name: &str| BoundHost::parse(name, &reserved).unwrap_err();
    assert_eq!(
        refused("*.fancy.com"),
        BindingError::Wildcard("*.fancy.com".into())
    );
    assert_eq!(
        refused("api.fancy.com:8443"),
        BindingError::Port("api.fancy.com:8443".into())
    );
    for address in [
        "1.2.3.4",
        "1.2.3.4:443",
        "[::1]",
        "[::1]:443",
        "::1",
        "10.0.0.300",
        "1.2.3.0x4",
        "a.0x10",
        "api.fancy.9com",
    ] {
        assert_eq!(
            refused(address),
            BindingError::IpAddress(address.into()),
            "{address}"
        );
    }
    for name in [
        "fancy",
        "api.local",
        "db.svc",
        "x.cluster.local",
        "a.internal",
        "localhost",
    ] {
        assert_eq!(
            refused(name),
            BindingError::NotPublic(name.into()),
            "{name}"
        );
    }
    for name in [
        "",
        "api.fancy.com.",
        ".fancy.com",
        "api..fancy.com",
        "-api.fancy.com",
        "api-.fancy.com",
        "api_x.fancy.com",
        "bücher.example",
        "api.fancy.com:abc",
        "https://api.fancy.com",
    ] {
        assert_eq!(
            refused(name),
            BindingError::InvalidHost(name.into()),
            "{name}"
        );
    }
    let long_label = format!("{}.example", "a".repeat(64));
    assert!(matches!(refused(&long_label), BindingError::InvalidHost(_)));
}

#[test]
fn provider_and_deployment_hosts_are_refused() {
    let reserved = reserved();
    for name in [
        "api.anthropic.com",
        "api.openai.com",
        "chatgpt.com",
        "ab.chatgpt.com",
        "a.b.chatgpt.com",
        "auth.openai.com",
        "platform.claude.com",
        "github.com",
        "api.github.com",
    ] {
        assert_eq!(
            BoundHost::parse(name, &reserved),
            Err(BindingError::ProviderHost(name.into())),
            "{name}"
        );
    }
    assert_eq!(
        BoundHost::parse("Registry.Example.dev", &reserved),
        Err(BindingError::DeploymentHost("registry.example.dev".into()))
    );
    for name in [
        "preview.example.dev",
        "app-1.preview.example.dev",
        "a.b.preview.example.dev",
    ] {
        assert_eq!(
            BoundHost::parse(name, &reserved),
            Err(BindingError::DeploymentHost(name.into())),
            "{name}"
        );
    }
    assert!(BoundHost::parse("xpreview.example.dev", &reserved).is_ok());
    for entry in [
        "*.",
        "*.*.example.dev",
        "**.example.dev",
        "*",
        "a b.example",
        "example.dev.",
    ] {
        assert!(ReservedHosts::new([entry]).is_err(), "{entry}");
    }
}

#[test]
fn every_front_door_provider_host_is_refused() {
    for entry in FRONT_DOOR_HOSTS {
        assert!(is_provider_host(entry.host), "{}", entry.host);
    }
}

#[test]
fn refused_headers_are_refused_in_any_case() {
    for name in [
        "Host",
        "COOKIE",
        "set-cookie",
        "Content-Length",
        "Content-Type",
        "Content-Encoding",
        "Transfer-Encoding",
        "Connection",
        "Keep-Alive",
        "Upgrade",
        "TE",
        "Trailer",
        "Expect",
        "Via",
        "Max-Forwards",
        "Early-Data",
        "Forwarded",
        "X-Forwarded-For",
        "x-forwarded-host",
        "Proxy-Authorization",
        "Origin",
        "Referer",
        "User-Agent",
        "X-Request-Id",
        "Traceparent",
        "Tracestate",
        "Codewire-Refusal",
    ] {
        assert_eq!(
            BoundHeader::parse(name).unwrap_err(),
            BindingError::RefusedHeader(name.into()),
            "{name}"
        );
    }
    for name in ["", ":authority", "X Api Key", "X-Api-Key:", "Ä"] {
        assert_eq!(
            BoundHeader::parse(name).unwrap_err(),
            BindingError::InvalidHeader(name.into()),
            "{name:?}"
        );
    }
    assert!(BoundHeader::parse("X-Api-Key").is_ok());
    assert!(BoundHeader::parse("authorization").is_ok());
}

#[test]
fn a_header_presentation_takes_one_or_two_distinct_headers() {
    assert_eq!(
        Presentation::header(Vec::new(), Scheme::parse("Bearer").unwrap()).unwrap(),
        Presentation::default_header()
    );
    let header = |name| BoundHeader::parse(name).unwrap();
    assert_eq!(
        Presentation::header(vec![header("X-Api-Key"), header("x-api-key")], Scheme::None),
        Err(BindingError::DuplicateHeader("x-api-key".into()))
    );
    assert_eq!(
        Presentation::header(vec![header("A"), header("B"), header("C")], Scheme::None),
        Err(BindingError::TooManyHeaders)
    );
    assert!(Presentation::header(vec![header("X-Api-Key"), header("X-Key")], Scheme::None).is_ok());
}

#[test]
fn a_scheme_is_one_token_or_none() {
    assert_eq!(Scheme::parse("none").unwrap(), Scheme::None);
    assert_eq!(Scheme::parse("NONE").unwrap(), Scheme::None);
    assert_eq!(
        Scheme::parse("token").unwrap(),
        Scheme::Word("token".into())
    );
    for scheme in ["", "Bearer token", "Bear:er", "é"] {
        assert_eq!(
            Scheme::parse(scheme),
            Err(BindingError::InvalidScheme),
            "{scheme:?}"
        );
    }
}

#[test]
fn a_basic_user_name_defaults_and_is_checked() {
    assert_eq!(
        Presentation::basic(None).unwrap(),
        Presentation::Basic {
            username: DEFAULT_BASIC_USERNAME.into()
        }
    );
    for username in ["", "a:b", "a b", &"u".repeat(65)] {
        assert_eq!(
            Presentation::basic(Some(username)),
            Err(BindingError::InvalidUsername),
            "{username:?}"
        );
    }
}

#[test]
fn a_prefix_is_short_plain_and_never_holds_the_marker() {
    assert!(PlaceholderPrefix::parse("ft_").is_ok());
    assert!(PlaceholderPrefix::parse("sk-live_").is_ok());
    for prefix in ["", "cwp1_", "x_cwp1_", "a b", "a.b", &"p".repeat(17)] {
        assert_eq!(
            PlaceholderPrefix::parse(prefix),
            Err(BindingError::InvalidPrefix),
            "{prefix:?}"
        );
    }
}

#[test]
fn a_binding_names_one_to_sixteen_distinct_hosts() {
    assert_eq!(
        HostBinding::new(Vec::new(), Presentation::default_header(), None),
        Err(BindingError::NoHosts)
    );
    let many = (0..=MAX_BOUND_HOSTS)
        .map(|index| host(&format!("h{index}.fancy.com")))
        .collect();
    assert_eq!(
        HostBinding::new(many, Presentation::default_header(), None),
        Err(BindingError::TooManyHosts)
    );
    assert_eq!(
        HostBinding::new(
            vec![host("api.fancy.com"), host("API.fancy.com")],
            Presentation::default_header(),
            None
        ),
        Err(BindingError::DuplicateHost("api.fancy.com".into()))
    );
    let bound = binding(&["api.fancy.com"], Presentation::default_header(), None);
    assert!(bound.names("api.fancy.com"));
    assert!(!bound.names("api2.fancy.com"));
}

#[test]
fn a_value_is_printable_ascii_up_to_eight_kib() {
    let bound = binding(&["api.fancy.com"], Presentation::default_header(), None);
    assert!(bound.validate_value(b"ft_value-1").is_ok());
    assert!(bound.validate_value(&[b'a'; MAX_BOUND_VALUE_BYTES]).is_ok());
    for value in [
        &b""[..],
        b"tab\there",
        b"new\nline",
        "é".as_bytes(),
        &[b'a'; MAX_BOUND_VALUE_BYTES + 1],
    ] {
        assert_eq!(bound.validate_value(value), Err(BindingError::InvalidValue));
    }
    let basic_user = binding(&["api.fancy.com"], Presentation::BasicUser, None);
    assert_eq!(
        basic_user.validate_value(b"user:pass"),
        Err(BindingError::BasicUserColon)
    );
    let basic = binding(&["api.fancy.com"], Presentation::basic(None).unwrap(), None);
    assert!(basic.validate_value(b"a:b").is_ok());
}

#[test]
fn widening_or_redirecting_a_binding_needs_the_value() {
    let one = binding(&["a.fancy.com"], Presentation::default_header(), None);
    let two = binding(
        &["a.fancy.com", "b.fancy.com"],
        Presentation::default_header(),
        None,
    );
    let other = binding(&["b.fancy.com"], Presentation::default_header(), None);
    let x_key = binding(
        &["a.fancy.com"],
        Presentation::header(vec![BoundHeader::parse("X-Key").unwrap()], Scheme::None).unwrap(),
        None,
    );
    let basic = binding(&["a.fancy.com"], Presentation::basic(None).unwrap(), None);
    let prefixed = binding(
        &["a.fancy.com"],
        Presentation::default_header(),
        Some("ft_"),
    );

    assert!(change_needs_value(None, Some(&one)), "plain to bound");
    assert!(change_needs_value(Some(&one), None), "bound to plain");
    assert!(change_needs_value(Some(&one), Some(&two)), "a host added");
    assert!(
        change_needs_value(Some(&one), Some(&other)),
        "a host replaced"
    );
    assert!(
        change_needs_value(Some(&one), Some(&x_key)),
        "another header"
    );
    assert!(
        change_needs_value(Some(&one), Some(&basic)),
        "another presentation"
    );

    assert!(!change_needs_value(None, None), "plain stays plain");
    assert!(
        !change_needs_value(Some(&two), Some(&one)),
        "a host removed"
    );
    assert!(!change_needs_value(Some(&one), Some(&prefixed)), "a prefix");
    assert!(!change_needs_value(Some(&one), Some(&one)), "no change");
}

#[test]
fn only_the_presentation_the_prefix_or_protection_moves_the_generation() {
    let one = binding(&["a.fancy.com"], Presentation::default_header(), None);
    let two = binding(
        &["a.fancy.com", "b.fancy.com"],
        Presentation::default_header(),
        None,
    );
    let basic = binding(&["a.fancy.com"], Presentation::BasicUser, None);
    let prefixed = binding(
        &["a.fancy.com"],
        Presentation::default_header(),
        Some("ft_"),
    );

    assert!(change_moves_generation(None, Some(&one)));
    assert!(change_moves_generation(Some(&one), None));
    assert!(change_moves_generation(Some(&one), Some(&basic)));
    assert!(change_moves_generation(Some(&one), Some(&prefixed)));
    assert!(!change_moves_generation(Some(&one), Some(&two)));
    assert!(!change_moves_generation(Some(&two), Some(&one)));
    assert!(!change_moves_generation(Some(&one), Some(&one)));
}
