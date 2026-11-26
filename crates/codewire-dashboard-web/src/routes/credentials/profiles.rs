//! Creating and updating access profiles from Settings → Credentials.
//!
//! When an update form omits `gemini` or `antigravity` (`None`, before the Edit
//! Profile template renders selectors for them), the profile's existing binding
//! for each omitted slot at the observed revision is preserved rather than
//! silently dropped (#6555).

use axum::{Form, extract::State, http::HeaderMap, response::Response};
use codewire_proto::codewire::v1::{AccessProfile, AccessProfileEntry};

use super::{
    CredentialQuery, mutation_cookie, mutation_error, page_error_redirect, page_redirect,
    row_action_dialog, valid_name, valid_revision,
};
use crate::{
    credentials_connect,
    environment_source_forms::exact_id,
    state::AppState,
    view::{CredentialProfileCreateSubmission, CredentialProfileUpdateSubmission},
};

pub(in crate::routes) async fn create_profile_action(
    State(state): State<AppState>,
    CredentialQuery(query): CredentialQuery,
    headers: HeaderMap,
    Form(form): Form<CredentialProfileCreateSubmission>,
) -> Response {
    let dialog = "create-profile";
    let cookie = match mutation_cookie(&state, &headers, &form.csrf, &query).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    let name = form.name.trim();
    if !valid_name(name) {
        return page_error_redirect("profile-invalid", dialog, &query, &headers);
    }
    let entries = match entries(
        form.codex,
        form.openai,
        form.anthropic,
        form.gemini,
        form.antigravity,
        form.ssh,
    ) {
        Ok(entries) => entries,
        Err(()) => return page_error_redirect("profile-invalid", dialog, &query, &headers),
    };
    match credentials_connect::create_profile(&state, cookie, name.into(), entries).await {
        Ok(()) => page_redirect("profile-created", false, &query, &headers),
        Err(error) => mutation_error(error.code, false, dialog, &query, &headers),
    }
}

pub(in crate::routes) async fn update_profile_action(
    State(state): State<AppState>,
    CredentialQuery(query): CredentialQuery,
    headers: HeaderMap,
    Form(form): Form<CredentialProfileUpdateSubmission>,
) -> Response {
    let dialog = row_action_dialog("profile", &form.profile_id, "edit");
    let cookie = match mutation_cookie(&state, &headers, &form.csrf, &query).await {
        Ok(cookie) => cookie,
        Err(response) => return response,
    };
    if exact_id(&form.profile_id).is_err() || !valid_revision(form.expected_revision) {
        return page_error_redirect("profile-invalid", &dialog, &query, &headers);
    }
    let (explicit_gemini, preserve_gemini) = match form.gemini {
        Some(value) => (value, false),
        None => (String::new(), true),
    };
    let (explicit_antigravity, preserve_antigravity) = match form.antigravity {
        Some(value) => (value, false),
        None => (String::new(), true),
    };
    let mut profile_entries = match entries(
        form.codex,
        form.openai,
        form.anthropic,
        explicit_gemini,
        explicit_antigravity,
        form.ssh,
    ) {
        Ok(entries) => entries,
        Err(()) => return page_error_redirect("profile-invalid", &dialog, &query, &headers),
    };
    if preserve_gemini || preserve_antigravity {
        let existing = match credentials_connect::get_profile_revision(
            &state,
            cookie.clone(),
            &form.profile_id,
            form.expected_revision,
        )
        .await
        {
            Ok(profile) => profile,
            Err(error) => return mutation_error(error.code, false, &dialog, &query, &headers),
        };
        if preserve_gemini
            && append_preserved_slot(&existing, "gemini", &mut profile_entries).is_err()
        {
            return page_error_redirect("profile-invalid", &dialog, &query, &headers);
        }
        if preserve_antigravity
            && append_preserved_slot(&existing, "antigravity", &mut profile_entries).is_err()
        {
            return page_error_redirect("profile-invalid", &dialog, &query, &headers);
        }
    }
    match credentials_connect::update_profile(
        &state,
        cookie,
        form.profile_id,
        form.expected_revision,
        profile_entries,
    )
    .await
    {
        Ok(()) => page_redirect("profile-updated", false, &query, &headers),
        Err(error) => mutation_error(error.code, false, &dialog, &query, &headers),
    }
}

pub(super) fn entries(
    codex: String,
    openai: String,
    anthropic: String,
    gemini: String,
    antigravity: String,
    ssh: String,
) -> Result<Vec<AccessProfileEntry>, ()> {
    let mut entries = Vec::new();
    for (slot, credential_id) in [
        ("codex", codex),
        ("openai", openai),
        ("anthropic", anthropic),
        ("gemini", gemini),
        ("antigravity", antigravity),
        ("ssh", ssh),
    ] {
        if credential_id.is_empty() {
            continue;
        }
        exact_id(&credential_id)?;
        entries.push(AccessProfileEntry {
            capability_slot: slot.into(),
            credential_id,
            ..Default::default()
        });
    }
    Ok(entries)
}

fn append_preserved_slot(
    existing: &AccessProfile,
    slot: &'static str,
    target: &mut Vec<AccessProfileEntry>,
) -> Result<(), ()> {
    let Some(entry) = existing
        .entries
        .iter()
        .find(|entry| entry.capability_slot == slot)
    else {
        return Ok(());
    };
    exact_id(&entry.credential_id)?;
    target.push(AccessProfileEntry {
        capability_slot: slot.into(),
        credential_id: entry.credential_id.clone(),
        ..Default::default()
    });
    Ok(())
}

#[cfg(test)]
#[path = "profile_update_tests.rs"]
mod tests;
