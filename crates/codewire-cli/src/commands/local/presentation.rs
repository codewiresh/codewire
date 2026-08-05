//! Stable JSON and text presentation for local runtime commands.

use super::*;

pub(crate) fn format_local_instance_list_text(entries: &[LocalInstanceEntry]) -> String {
    if entries.is_empty() {
        return "No local instances found.\n".to_string();
    }
    let mut output = format!(
        "{:<20} {:<10} {:<10} {:<18} {:<20} {}\n",
        "NAME", "BACKEND", "STATE", "PORTS", "IMAGE", "REPO"
    );
    for entry in entries {
        output.push_str(&format!(
            "{:<20} {:<10} {:<10} {:<18} {:<20} {}\n",
            entry.name,
            entry.backend,
            entry.status,
            local_port_summary(entry),
            entry.image,
            entry.repo_path
        ));
    }
    output
}

pub(crate) fn format_local_instance_info_text(entry: &LocalInstanceEntry) -> String {
    let mut output = String::new();
    output.push_str(&format!("{:<10} {}\n", "Name:", entry.name));
    output.push_str(&format!("{:<10} {}\n", "Backend:", entry.backend));
    output.push_str(&format!("{:<10} {}\n", "State:", entry.status));
    output.push_str(&format!("{:<10} {}\n", "Runtime:", entry.runtime_name));
    output.push_str(&format!("{:<10} {}\n", "Image:", entry.image));
    output.push_str(&format!("{:<10} {}\n", "Repo:", entry.repo_path));
    output.push_str(&format!("{:<10} {}\n", "Workdir:", entry.workdir));
    let ports = local_port_summary(entry);
    if !ports.is_empty() {
        output.push_str(&format!("{:<10} {}\n", "Ports:", ports));
    }
    if let Some(lima) = &entry.lima {
        if !lima.vm_type.is_empty() {
            output.push_str(&format!("{:<10} {}\n", "VMType:", lima.vm_type));
        }
        if !lima.mount_type.is_empty() {
            output.push_str(&format!("{:<10} {}\n", "MountType:", lima.mount_type));
        }
    }
    if !entry.preset.is_empty() {
        output.push_str(&format!("{:<10} {}\n", "Preset:", entry.preset));
    }
    if !entry.install.is_empty() {
        output.push_str(&format!("{:<10} {}\n", "Install:", entry.install));
    }
    if !entry.startup.is_empty() {
        output.push_str(&format!("{:<10} {}\n", "Startup:", entry.startup));
    }
    if !entry.created_at.is_empty() {
        output.push_str(&format!("{:<10} {}\n", "Created:", entry.created_at));
    }
    output
}

pub(crate) fn format_local_resize_text(entry: &LocalInstanceEntry) -> String {
    let mut output = String::new();
    output.push_str(&format!("{:<10} {}\n", "State:", entry.status));
    if entry.cpu > 0 {
        output.push_str(&format!("{:<10} {}m\n", "CPU:", entry.cpu));
    }
    if entry.memory > 0 {
        output.push_str(&format!(
            "{:<10} {}\n",
            "Memory:",
            local_runtime_memory_label(entry.memory)
        ));
    }
    if entry.disk > 0 {
        output.push_str(&format!("{:<10} {}GiB\n", "Disk:", entry.disk));
    }
    output
}

pub(crate) fn local_runtime_memory_label(memory_mb: i32) -> String {
    if memory_mb > 0 && memory_mb % 1024 == 0 {
        format!("{}GiB", memory_mb / 1024)
    } else {
        format!("{memory_mb}MB")
    }
}

pub(crate) fn local_port_summary(entry: &LocalInstanceEntry) -> String {
    entry
        .ports
        .iter()
        .filter_map(|port| local_port_display(entry, port))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn format_local_ports_text(entry: &LocalInstanceEntry) -> String {
    let mut lines = entry
        .ports
        .iter()
        .filter_map(|port| local_port_display(entry, port))
        .map(|display| format!("  {display}\n"))
        .collect::<String>();
    if lines.is_empty() {
        lines.push_str("No ports configured.\n");
    }
    lines
}

pub(crate) fn format_local_files_text(entries: &[LocalFileEntry]) -> String {
    entries
        .iter()
        .map(|entry| {
            let kind = if entry.is_dir { "dir" } else { "file" };
            format!("{kind}\t{}\t{}\t{}\n", entry.mode, entry.size, entry.name)
        })
        .collect()
}

pub(crate) fn local_port_display(
    entry: &LocalInstanceEntry,
    port: &LocalPortEntry,
) -> Option<String> {
    if port.host_port <= 0 || port.guest_port <= 0 {
        return None;
    }
    let mut display = if port.host_port != port.guest_port || entry.backend == "lima" {
        format!("{} -> {}", port.host_port, port.guest_port)
    } else {
        port.guest_port.to_string()
    };
    if let Some(label) = trimmed_str(&port.label) {
        display.push_str(" (");
        display.push_str(label);
        display.push(')');
    }
    Some(display)
}

pub(crate) fn is_zero_i32(value: &i32) -> bool {
    *value == 0
}

pub(crate) fn is_false(value: &bool) -> bool {
    !*value
}
