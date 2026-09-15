use super::*;

#[test]
fn canonical_platform_authority_bytes_are_stable_and_unknown_fields_fail() {
    let golden = include_bytes!("testdata/platform-source-authority.json");
    let authority: PlatformSourceAuthority = serde_json::from_slice(golden).unwrap();
    assert_eq!(
        authority.profile_slots,
        BTreeSet::from(["codex".to_owned(), "openai".to_owned()])
    );
    let mut encoded = serde_json::to_vec(&authority).unwrap();
    encoded.push(b'\n');
    assert_eq!(encoded, golden.to_vec());

    let mut unknown = serde_json::to_value(authority).unwrap();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("future".to_owned(), serde_json::Value::Null);
    assert!(serde_json::from_value::<PlatformSourceAuthority>(unknown).is_err());
}
