//! Request validation for the permanently raw JSON routes.
//!
//! Connect owns every control-plane procedure and validates through its own
//! messages. The raw routes that remain, identity above all, take their body
//! through this extractor: the request type derives `JsonSchema`, and the
//! schema generated from it rejects type- or shape-invalid input with the
//! stable 422 envelope before the handler runs.

use std::borrow::Cow;

use axum::Json;
use axum::extract::FromRequest;
use jsonschema::ValidationError;
use schemars::JsonSchema;
use serde::de::DeserializeOwned;

use crate::error::{AppError, ValidationIssue};

/// JSON body extractor that rejects type/shape-invalid payloads before
/// handlers run.
#[derive(Debug, Clone, Copy, Default)]
pub struct ValidatedJson<T>(pub T);

impl<S, T> FromRequest<S> for ValidatedJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned + JsonSchema,
{
    type Rejection = AppError;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<serde_json::Value>::from_request(req, state)
            .await
            .map_err(|rejection| AppError::BadRequest(Cow::Owned(rejection.body_text())))?;
        validate_value::<T>(value).map(Self)
    }
}

/// Validate and deserialize a raw JSON value as `T`.
pub fn validate_value<T>(value: serde_json::Value) -> Result<T, AppError>
where
    T: DeserializeOwned + JsonSchema,
{
    let schema = serde_json::to_value(schemars::schema_for!(T)).map_err(|e| {
        AppError::InternalMsg(Cow::Owned(format!(
            "failed to serialize generated request schema: {e}"
        )))
    })?;
    let validator = jsonschema::validator_for(&schema).map_err(|e| {
        AppError::InternalMsg(Cow::Owned(format!(
            "failed to compile generated request schema: {e}"
        )))
    })?;

    let errors: Vec<_> = validator
        .iter_errors(&value)
        .map(|e| ValidationIssue {
            path: schema_validation_path(&e),
            message: Cow::Owned(e.to_string()),
        })
        .collect();
    if !errors.is_empty() {
        return Err(AppError::Validation { errors });
    }

    serde_json::from_value(value).map_err(|e| AppError::Validation {
        errors: vec![ValidationIssue {
            path: serde_validation_path(&e),
            message: Cow::Owned(e.to_string()),
        }],
    })
}

fn schema_validation_path(error: &ValidationError<'_>) -> Cow<'static, str> {
    let path = error.instance_path().to_string();
    if path.is_empty() {
        Cow::Borrowed("/")
    } else {
        Cow::Owned(path)
    }
}

fn serde_validation_path(error: &serde_json::Error) -> Cow<'static, str> {
    match error.line() {
        0 => Cow::Borrowed("/"),
        _ => Cow::Owned(format!("/line/{}/column/{}", error.line(), error.column())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, JsonSchema)]
    struct Invite {
        email: String,
        role: String,
    }

    #[test]
    fn accepts_values_matching_the_generated_schema() {
        let value = serde_json::json!({
            "email": "n@example.com",
            "role": "admin"
        });

        let parsed = validate_value::<Invite>(value).expect("valid request");
        assert_eq!(parsed.email, "n@example.com");
        assert_eq!(parsed.role, "admin");
    }

    #[test]
    fn rejects_values_missing_schema_required_fields() {
        let value = serde_json::json!({
            "email": "n@example.com"
        });

        let Err(AppError::Validation { errors }) = validate_value::<Invite>(value) else {
            panic!("expected validation error");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/");
        assert!(errors[0].message.contains("role"));
    }

    #[test]
    fn rejects_values_that_do_not_match_schema_types() {
        let value = serde_json::json!({
            "email": "n@example.com",
            "role": 7
        });

        let Err(AppError::Validation { errors }) = validate_value::<Invite>(value) else {
            panic!("expected validation error");
        };

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "/role");
        assert!(errors[0].message.contains("string"));
    }
}
