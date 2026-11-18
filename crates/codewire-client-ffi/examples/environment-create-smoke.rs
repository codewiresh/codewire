//! The iOS Create sheet's create against a real server (#3825, `ios-create`
//! in `docs/journeys/ios-app.md`): the app's own `create_from_form`, the
//! dashboard's rules, the public Connect API. Given a preset with the
//! cluster's workspace image, it shows an empty form refused before anything
//! is sent, creates from the preset alone, as the owner did on 2026-11-16,
//! reads back the project the server saved, and deletes the environment.

use anyhow::{Context as _, bail, ensure};
use codewire_client::{
    ClientConfig, CodewireClient, DeleteEnvironmentRequest, GetEnvironmentProjectSpecRequest,
    StaticTokenProvider,
};
use codewire_client_ffi::{CreateForm, CreateOutcome, FormField, create_from_form};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base_url = required_env("SMOKE_CONNECT_BASE_URL")?;
    let org_id = required_env("SMOKE_ORG_ID")?;
    let access_token = required_env("SMOKE_ACCESS_TOKEN")?;
    let image = required_env("SMOKE_WORKSPACE_IMAGE")?;
    let preset_id = required_env("SMOKE_PRESET_ID")?;
    let run = required_env("SMOKE_RUN_ID")?;
    let http = match std::env::var("SMOKE_CA_CERT_FILE") {
        Ok(path) => {
            let pem =
                std::fs::read(&path).with_context(|| format!("read CA certificate {path}"))?;
            reqwest::Client::builder()
                .add_root_certificate(reqwest::Certificate::from_pem(&pem).context("parse CA PEM")?)
                .build()
                .context("build TLS client")?
        }
        Err(_) => reqwest::Client::new(),
    };
    let client = CodewireClient::with_http(
        ClientConfig::new(&base_url)?.with_user_agent("codewire-environment-create-smoke/1")?,
        StaticTokenProvider::new(access_token)?,
        http,
    )?;

    from_the_preset(&client, &org_id, &preset_id, &image, &run).await?;
    println!("environment-create-smoke: PASS");
    Ok(())
}

async fn from_the_preset(
    client: &CodewireClient,
    org_id: &str,
    preset_id: &str,
    image: &str,
    run: &str,
) -> anyhow::Result<()> {
    match create_from_form(client, org_id, CreateForm::default()).await? {
        CreateOutcome::Refused { refusals }
            if refusals
                .iter()
                .map(|refusal| refusal.field)
                .eq([FormField::Image]) => {}
        other => bail!("an empty form was not refused for its image alone: {other:?}"),
    }

    let form = CreateForm {
        name: format!("kind-create-{run}"),
        preset_id: preset_id.to_owned(),
        ..Default::default()
    };
    let environment = match create_from_form(client, org_id, form).await? {
        CreateOutcome::Created { environment } => environment,
        CreateOutcome::Refused { refusals } => {
            bail!("the preset alone was refused: {refusals:?}")
        }
    };
    let saved = client
        .get_environment_project_spec(GetEnvironmentProjectSpecRequest {
            org_id: org_id.to_owned(),
            environment_id: environment.id.clone(),
            ..Default::default()
        })
        .await
        .context("read the created environment's project");
    let removed = client
        .delete_environment(DeleteEnvironmentRequest {
            org_id: org_id.to_owned(),
            environment_id: environment.id.clone(),
            ..Default::default()
        })
        .await
        .context("delete the created environment");
    let saved_image = saved?
        .project_spec
        .into_option()
        .context("the server saved no project for the environment")?
        .image;
    ensure!(
        saved_image == image,
        "the environment's project has image {saved_image:?}, not the preset's {image:?}"
    );
    removed?;
    Ok(())
}

fn required_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}
