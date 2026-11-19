//! Creates an environment, runs a command in it, writes and reads back a
//! file, and deletes it. Reads `CODEWIRE_API_KEY`, `CODEWIRE_ORG_ID` and,
//! for a server other than the hosted one, `CODEWIRE_API_URL`.
//!
//! ```sh
//! cargo run -p codewire --example quickstart
//! ```

use std::process::ExitCode;

use codewire::{
    ClientError, Codewire, CreateEnvironmentRequest, EnvironmentHandle, ErrorCode, ExecRequest,
    ListFilesRequest, ProjectSpec,
};

#[tokio::main]
async fn main() -> ExitCode {
    match quickstart().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("quickstart failed: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn quickstart() -> Result<(), ClientError> {
    let codewire = Codewire::from_env()?;
    let mut environment = codewire
        .create_environment(CreateEnvironmentRequest {
            name: Some("rust-sdk-quickstart".into()),
            project_spec: ProjectSpec {
                schema_version: 1,
                image: "python:3.12-slim".into(),
                working_directory: "/workspace".into(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        })
        .await?;
    println!("created {}", environment.id());

    // Delete the environment whether or not the steps succeeded.
    let steps = use_environment(&mut environment).await;
    let deleted = environment.delete().await;
    if deleted.is_ok() {
        println!("deleted {}", environment.id());
    }
    steps.and(deleted)
}

async fn use_environment(environment: &mut EnvironmentHandle) -> Result<(), ClientError> {
    environment.wait_ready().await?;
    println!("ready");

    let output = environment
        .exec(ExecRequest {
            command: vec!["python3".into(), "--version".into()],
            ..Default::default()
        })
        .await?;
    print!("{}", String::from_utf8_lossy(&output.stdout));
    if output.exit_code != 0 {
        return Err(failed(format!("python3 exited {}", output.exit_code)));
    }

    environment
        .upload("/workspace/hello.txt", &b"hello from Rust"[..])
        .await?;
    let listing = environment
        .list_files(ListFilesRequest {
            path: "/workspace".into(),
            ..Default::default()
        })
        .await?;
    if !listing
        .entries
        .iter()
        .any(|entry| entry.name == "hello.txt")
    {
        return Err(failed("hello.txt is missing from /workspace"));
    }
    let contents = environment.download("/workspace/hello.txt").await?;
    if contents != b"hello from Rust" {
        return Err(failed("hello.txt came back different"));
    }
    println!("wrote and read back /workspace/hello.txt");
    Ok(())
}

fn failed(message: impl Into<String>) -> ClientError {
    ClientError::new(ErrorCode::Unknown, message)
}
