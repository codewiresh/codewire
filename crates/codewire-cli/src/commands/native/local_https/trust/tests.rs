use super::*;

/// A real certificate, from a throwaway CA rcgen made for this test.
fn throwaway_ca(directory: &Path) -> LocalCaCertificate {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Codewire local HTTPS CA");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    let certificate = params.self_signed(&key).unwrap();
    let path = directory.join("ca.pem");
    std::fs::write(&path, certificate.pem()).unwrap();
    LocalCaCertificate::read(&path).unwrap()
}

/// The fake certutil, run from the repository: a copy under a temporary
/// directory can't run where `/tmp` is mounted noexec, as on CI guests.
fn fake_certutil() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/commands/native/local_https/trust/fake-certutil.sh")
}

fn store(directory: PathBuf, certutil: &Path) -> Store {
    Store {
        directory,
        certutil: certutil.to_owned(),
    }
}

/// The trust flags of every entry in a fake database, by fingerprint prefix.
fn flags(store: &Store) -> Vec<String> {
    let mut found: Vec<String> = std::fs::read_dir(&store.directory)
        .map(|entries| {
            entries
                .flatten()
                .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "flags"))
                .map(|entry| {
                    std::fs::read_to_string(entry.path())
                        .unwrap()
                        .trim()
                        .to_owned()
                })
                .collect()
        })
        .unwrap_or_default();
    found.sort();
    found
}

#[test]
fn a_certificate_is_named_by_its_fingerprint() {
    let directory = tempfile::tempdir().unwrap();
    let ca = throwaway_ca(directory.path());
    assert_eq!(ca.fingerprint.len(), 64);
    assert!(
        ca.fingerprint
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase())
    );
    assert_eq!(
        ca.nickname(),
        format!("Codewire local HTTPS CA {}", &ca.fingerprint[..16])
    );
    let other = throwaway_ca(tempfile::tempdir().unwrap().path());
    assert_ne!(
        ca.nickname(),
        other.nickname(),
        "a rotated CA gets its own name"
    );
}

#[test]
fn only_one_pem_certificate_is_read() {
    assert!(pem_der("not a certificate").is_none());
    assert!(pem_der("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n").is_none());
}

#[test]
fn certutil_listings_yield_only_this_features_nicknames() {
    let listing = "\nCertificate Nickname                                         Trust Attributes\n\
                   \x20                                                            SSL,S/MIME,JAR/XPI\n\n\
                   Codewire local HTTPS CA 0123456789ABCDEF                     C,,   \n\
                   Some Other CA                                                CT,C,C\n\
                   Codewire local HTTPS CA FEDCBA9876543210                     C,,\n";
    assert_eq!(
        codewire_nicknames(listing),
        [
            "Codewire local HTTPS CA 0123456789ABCDEF",
            "Codewire local HTTPS CA FEDCBA9876543210"
        ]
    );
}

/// Trust adds the CA once with `C,,`, and removes an older Codewire CA it
/// finds; untrust removes exactly this CA.
#[test]
fn trust_adds_this_ca_once_and_clears_older_ones() {
    let certutil = fake_certutil();
    let databases = tempfile::tempdir().unwrap();
    let store = store(databases.path().join("nssdb"), &certutil);
    let (old_dir, new_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (old, new) = (throwaway_ca(old_dir.path()), throwaway_ca(new_dir.path()));

    assert!(trust(&old, &store).unwrap(), "first trust adds");
    assert!(!trust(&old, &store).unwrap(), "a second trust adds nothing");
    assert_eq!(flags(&store), ["C,,"]);

    assert!(trust(&new, &store).unwrap());
    assert!(holds(&new, &store).unwrap());
    assert!(!holds(&old, &store).unwrap(), "the older CA is cleared");
    assert_eq!(flags(&store), ["C,,"]);

    assert!(untrust(&new, &store).unwrap());
    assert!(
        !untrust(&new, &store).unwrap(),
        "a second untrust finds nothing"
    );
    assert!(flags(&store).is_empty());
}

/// A rotation moves trust only in stores that held the old CA. When one
/// store fails, the error names it, every store still trusts some CA, and a
/// plain trust finishes the move.
#[test]
fn a_rotation_that_fails_part_way_leaves_every_store_trusting_a_ca() {
    let certutil = fake_certutil();
    let databases = tempfile::tempdir().unwrap();
    let first = store(databases.path().join("first"), &certutil);
    let second = store(databases.path().join("second"), &certutil);
    let untouched = store(databases.path().join("untouched"), &certutil);
    let (old_dir, new_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (old, new) = (throwaway_ca(old_dir.path()), throwaway_ca(new_dir.path()));
    trust(&old, &first).unwrap();
    trust(&old, &second).unwrap();
    ensure_database(&untouched).unwrap();
    let all = [first.clone(), second.clone(), untouched.clone()];

    std::fs::write(second.directory.join("fail-add"), "").unwrap();
    let error = format!("{:#}", move_trust(&old, &new, &all).unwrap_err());
    assert!(error.contains(&second.to_string()), "{error}");
    assert!(error.contains("cw local-https trust"), "{error}");
    assert!(holds(&new, &first).unwrap() && !holds(&old, &first).unwrap());
    assert!(
        holds(&old, &second).unwrap(),
        "a failed store keeps the old CA rather than none"
    );

    trust(&new, &second).unwrap();
    for store in [&first, &second] {
        assert!(holds(&new, store).unwrap() && !holds(&old, store).unwrap());
    }
    assert!(
        !holds(&new, &untouched).unwrap(),
        "trust isn't spread to new stores"
    );

    let moved = move_trust(&new, &old, &all).unwrap();
    assert_eq!(moved, [first, second]);
}

/// The same round trip against NSS's own tool, in a throwaway database.
#[test]
#[ignore = "needs NSS's certutil; run with --ignored"]
fn trust_and_untrust_change_only_this_ca_in_a_real_nss_database() {
    let directory = tempfile::tempdir().unwrap();
    let store = store(directory.path().join("nssdb"), Path::new(CERTUTIL));
    let ca = throwaway_ca(directory.path());
    let other_directory = tempfile::tempdir().unwrap();
    let other = throwaway_ca(other_directory.path());

    assert!(!holds(&ca, &store).unwrap());
    trust(&other, &store).unwrap();
    trust(&ca, &store).unwrap();
    assert!(holds(&ca, &store).unwrap());
    assert!(!holds(&other, &store).unwrap(), "trust clears the older CA");
    let listing = output(store.certutil().args(["-L", "-d", &store.database()])).unwrap();
    let row = listing
        .lines()
        .find(|line| line.starts_with(&ca.nickname()))
        .expect("the CA's entry");
    let flags = row.split_whitespace().last().unwrap();
    assert_eq!(
        flags, "C,,",
        "trusted as a TLS server CA only, never CT,C,C: {row}"
    );

    assert!(untrust(&ca, &store).unwrap());
    assert!(!holds(&ca, &store).unwrap());
    assert!(
        !untrust(&ca, &store).unwrap(),
        "a second untrust finds nothing"
    );
}
