#![cfg(feature = "openapi")]

use codewire_types::{InviteMemberRequest, OrgRole, UpdateMemberRoleRequest};

fn schema_json<T: schemars::JsonSchema>() -> serde_json::Value {
    serde_json::to_value(schemars::schema_for!(T)).expect("schema serializes")
}

fn required_fields(schema: &serde_json::Value) -> Vec<String> {
    schema
        .get("required")
        .and_then(|v| v.as_array())
        .expect("schema has required array")
        .iter()
        .map(|v| v.as_str().expect("required field is a string").to_owned())
        .collect()
}

#[test]
fn invite_member_schema_marks_non_optional_fields_required() {
    let schema = schema_json::<InviteMemberRequest>();

    assert_eq!(required_fields(&schema), vec!["email", "role"]);
    assert_eq!(
        schema.pointer("/properties/email/type"),
        Some(&serde_json::Value::String("string".to_owned()))
    );
}

#[test]
fn update_member_role_schema_marks_role_required() {
    let schema = schema_json::<UpdateMemberRoleRequest>();

    assert_eq!(required_fields(&schema), vec!["role"]);
}

#[test]
fn org_role_schema_preserves_wire_values() {
    let schema = schema_json::<OrgRole>();

    assert_eq!(
        schema.get("enum"),
        Some(&serde_json::json!(["owner", "admin", "member"]))
    );
}
