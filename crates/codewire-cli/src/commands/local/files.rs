//! Local runtime file-transfer command handling and output parsing.

use super::*;

pub(crate) fn handle_local_files_command(
    data_dir: &Path,
    args: LocalFilesArgs,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let current_dir = env::current_dir().context("current directory")?;
    match args.command {
        LocalFilesCommand::Upload(upload) => {
            let (_, instance) =
                resolve_local_instance_config(data_dir, Some(&upload.name), &current_dir)?;
            local_files_upload(&instance, &upload.remote_path)?;
            if matches!(output, OutputFormat::Json) {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "name": instance.name,
                        "remote_path": upload.remote_path,
                        "uploaded": true,
                    }))?
                );
            }
        }
        LocalFilesCommand::Download(download) => {
            let (_, instance) =
                resolve_local_instance_config(data_dir, Some(&download.name), &current_dir)?;
            local_files_download(&instance, &download.remote_path)?;
        }
        LocalFilesCommand::List(list) => {
            let (_, instance) =
                resolve_local_instance_config(data_dir, Some(&list.name), &current_dir)?;
            let entries = local_files_list(
                &instance,
                list.remote_path
                    .as_deref()
                    .and_then(trimmed_str)
                    .unwrap_or("/"),
            )?;
            match output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&entries)?),
                OutputFormat::Text => print!("{}", format_local_files_text(&entries)),
            }
        }
    }
    Ok(())
}

pub(crate) fn local_files_command_spec(
    instance: &config::LocalInstanceConfig,
    command: &[String],
) -> anyhow::Result<LocalRuntimeCommand> {
    if command.is_empty() {
        anyhow::bail!("no command specified");
    }
    match trimmed_required(&instance.backend, "local backend")? {
        "docker" => {
            let runtime = local_runtime_name(instance)?;
            let mut args = vec!["exec".to_string(), "-i".to_string(), runtime.to_string()];
            args.extend(command.iter().cloned());
            Ok(LocalRuntimeCommand {
                program: "docker".to_string(),
                args,
            })
        }
        "lima" => {
            let lima_name = local_lima_instance_name(instance)?;
            let mut args = vec![
                "shell".to_string(),
                "--workdir".to_string(),
                "/".to_string(),
                lima_name.to_string(),
                "sudo".to_string(),
                "docker".to_string(),
                "exec".to_string(),
                "-i".to_string(),
                LIMA_CONTAINER_NAME.to_string(),
            ];
            args.extend(command.iter().cloned());
            Ok(LocalRuntimeCommand {
                program: "limactl".to_string(),
                args,
            })
        }
        other => anyhow::bail!("unsupported local backend {other:?}"),
    }
}

pub(crate) fn local_files_upload(
    instance: &config::LocalInstanceConfig,
    remote_path: &str,
) -> anyhow::Result<()> {
    let remote_path = trimmed_required(remote_path, "remote path")?;
    let script = format!(
        "mkdir -p {} && cat > {}",
        shell_quote(&parent_dir(remote_path)),
        shell_quote(remote_path)
    );
    let spec = local_files_command_spec(instance, &["sh".to_string(), "-c".to_string(), script])?;
    let mut child = ProcessCommand::new(&spec.program)
        .args(&spec.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("start upload")?;
    let mut child_stdin = child.stdin.take().context("stdin pipe")?;
    let mut stdin = std::io::stdin().lock();
    let copy_result = std::io::copy(&mut stdin, &mut child_stdin).context("upload");
    drop(child_stdin);
    let status = child.wait().context("upload")?;
    copy_result?;
    if !status.success() {
        anyhow::bail!(
            "upload failed with exit code {}",
            status.code().unwrap_or(1)
        );
    }
    Ok(())
}

pub(crate) fn local_files_download(
    instance: &config::LocalInstanceConfig,
    remote_path: &str,
) -> anyhow::Result<()> {
    let remote_path = trimmed_required(remote_path, "remote path")?;
    let spec = local_files_command_spec(instance, &["cat".to_string(), remote_path.to_string()])?;
    let status = ProcessCommand::new(&spec.program)
        .args(&spec.args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("download")?;
    if !status.success() {
        anyhow::bail!(
            "download failed with exit code {}",
            status.code().unwrap_or(1)
        );
    }
    Ok(())
}

pub(crate) fn local_files_list(
    instance: &config::LocalInstanceConfig,
    remote_path: &str,
) -> anyhow::Result<Vec<LocalFileEntry>> {
    let remote_path = trimmed_str(remote_path).unwrap_or("/");
    let spec = local_files_command_spec(
        instance,
        &[
            "ls".to_string(),
            "-la".to_string(),
            "--time-style=full-iso".to_string(),
            remote_path.to_string(),
        ],
    )?;
    let output = ProcessCommand::new(&spec.program)
        .args(&spec.args)
        .output()
        .context("list")?;
    if !output.status.success() {
        if !output.stderr.is_empty() {
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
        }
        anyhow::bail!(
            "list failed with exit code {}",
            output.status.code().unwrap_or(1)
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_ls_output(&stdout))
}

pub(crate) fn parse_ls_output(output: &str) -> Vec<LocalFileEntry> {
    let mut entries = Vec::new();
    for line in output.lines() {
        if line.starts_with("total ") || line.trim().is_empty() {
            continue;
        }
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 9 {
            continue;
        }
        let mode = parts[0];
        let size = parts[4].parse::<i64>().unwrap_or_default();
        let mtime = format!("{} {} {}", parts[5], parts[6], parts[7]);
        let mut name = extract_ls_name(line, &parts[..8]);
        if name == "." || name == ".." {
            continue;
        }
        if let Some((link_name, _)) = name.split_once(" -> ") {
            name = link_name.to_string();
        }
        entries.push(LocalFileEntry {
            name,
            size,
            is_dir: mode.starts_with('d'),
            mode: mode.to_string(),
            mtime,
        });
    }
    entries
}

pub(crate) fn extract_ls_name(line: &str, prefix: &[&str]) -> String {
    let mut rest = line;
    for field in prefix {
        if let Some(index) = rest.find(field) {
            rest = &rest[index + field.len()..];
        } else {
            return rest.to_string();
        }
    }
    rest.trim_start_matches([' ', '\t']).to_string()
}

pub(crate) fn parent_dir(remote_path: &str) -> String {
    match remote_path.rfind('/') {
        Some(index) if index > 0 => remote_path[..index].to_string(),
        _ => "/".to_string(),
    }
}

pub(crate) fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
