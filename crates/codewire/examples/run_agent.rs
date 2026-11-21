//! Runs a coding agent in an environment on a small project, without a
//! terminal, and prints the change it made. Reads `CODEWIRE_API_KEY`,
//! `CODEWIRE_ORG_ID` and, for a server other than the hosted one,
//! `CODEWIRE_API_URL`.
//!
//! ```sh
//! cargo run -p codewire --example run_agent
//! ```
//!
//! `RUN_AGENT_COMMAND` replaces the agent command, which by default is Claude
//! Code without a terminal. Claude Code needs a Claude credential in the
//! environment; a program signed in with an API key can't bind a profile
//! yet (#5687).

use std::process::ExitCode;

use codewire::{
    ClientError, Codewire, CreateEnvironmentRequest, EnvironmentHandle, ErrorCode, ExecRequest,
    ExecResponse, ProjectSpec, ProtoDuration,
};

const PROJECT: &str = "/workspace/project";
const TASK: &str = "The test in test_greeting.py fails. Fix greeting.py so that it passes, without changing the test.";
const FILES: &[(&str, &str)] = &[
    (
        "greeting.py",
        "def greet(name):\n    return \"Hello \" + name\n",
    ),
    (
        "test_greeting.py",
        "import unittest\n\nfrom greeting import greet\n\n\n\
         class GreetingTest(unittest.TestCase):\n\
         \x20   def test_greets_by_name(self):\n\
         \x20       self.assertEqual(greet(\"Codewire\"), \"Hello, Codewire!\")\n\n\n\
         if __name__ == \"__main__\":\n\x20   unittest.main()\n",
    ),
];

#[tokio::main]
async fn main() -> ExitCode {
    match run_agent().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("run-agent failed: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run_agent() -> Result<(), ClientError> {
    let codewire = Codewire::from_env()?;
    let mut environment = codewire
        .create_environment(CreateEnvironmentRequest {
            name: Some("rust-sdk-run-agent".into()),
            project_spec: ProjectSpec {
                schema_version: 1,
                image: "workspace".into(),
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

async fn run(
    environment: &EnvironmentHandle,
    command: &str,
    seconds: i64,
) -> Result<ExecResponse, ClientError> {
    environment
        .exec(ExecRequest {
            command: vec!["sh".into(), "-c".into(), command.into()],
            working_dir: PROJECT.into(),
            timeout: ProtoDuration {
                seconds,
                ..Default::default()
            }
            .into(),
            ..Default::default()
        })
        .await
}

/// A command that exited non-zero, as an error naming what it was for.
fn succeeded(what: &str, output: &ExecResponse) -> Result<(), ClientError> {
    if output.exit_code == 0 {
        return Ok(());
    }
    Err(failed(format!(
        "{what} exited {}: {}",
        output.exit_code,
        String::from_utf8_lossy(&output.stderr)
    )))
}

async fn use_environment(environment: &mut EnvironmentHandle) -> Result<(), ClientError> {
    environment.wait_ready().await?;
    let created = environment
        .exec(ExecRequest {
            command: vec!["mkdir".into(), "-p".into(), PROJECT.into()],
            ..Default::default()
        })
        .await?;
    succeeded("mkdir", &created)?;
    for (name, contents) in FILES {
        environment
            .upload(&format!("{PROJECT}/{name}"), contents.as_bytes())
            .await?;
    }
    let baseline = run(
        environment,
        "git init -q && git add -A && git -c user.name=example -c user.email=example@example.com commit -qm baseline",
        300,
    )
    .await?;
    succeeded("git baseline", &baseline)?;
    if run(environment, "python3 -m unittest -q test_greeting", 300)
        .await?
        .exit_code
        == 0
    {
        return Err(failed("the test should fail before the agent runs"));
    }
    println!("uploaded the project; its test fails");

    let agent = std::env::var("RUN_AGENT_COMMAND")
        .ok()
        .map(|command| command.trim().to_owned())
        .filter(|command| !command.is_empty())
        .unwrap_or_else(|| format!("claude -p {TASK:?} --permission-mode acceptEdits"));
    succeeded("the agent", &run(environment, &agent, 900).await?)?;
    println!("the agent finished");

    let diff = run(environment, "git diff", 300).await?;
    succeeded("git diff", &diff)?;
    print!("{}", String::from_utf8_lossy(&diff.stdout));
    succeeded(
        "the test",
        &run(environment, "python3 -m unittest -q test_greeting", 300).await?,
    )?;
    println!("the test passes");
    Ok(())
}

fn failed(message: impl Into<String>) -> ClientError {
    ClientError::new(ErrorCode::Unknown, message)
}
