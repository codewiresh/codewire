"""Text-only helpers shared by rendered Kubernetes policy checks."""

from .shared import *


def documents(rendered: str) -> list[str]:
    return [
        document.strip()
        for document in re.split(r"^---\s*$", rendered, flags=re.MULTILINE)
        if document.strip()
    ]


def top_level_field(document: str, field: str) -> str | None:
    match = re.search(rf"^{re.escape(field)}:\s*(\S+)\s*$", document, re.MULTILINE)
    return match.group(1) if match else None


def metadata_field(document: str, field: str) -> str | None:
    lines = document.split("\n")
    try:
        metadata = lines.index("metadata:")
    except ValueError:
        return None
    for line in lines[metadata + 1 :]:
        if re.match(r"^[^ ]", line):
            break
        match = re.match(rf"^  {re.escape(field)}:\s*(\S+)\s*$", line)
        if match:
            return match.group(1)
    return None


def resource_name(document: str) -> str | None:
    return metadata_field(document, "name")


def top_level_block(document: str, field: str) -> str:
    lines = document.split("\n")
    start = next((index for index, line in enumerate(lines) if line == f"{field}:"), -1)
    if start < 0:
        return ""
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if re.match(r"^[A-Za-z][A-Za-z0-9_.-]*:", lines[index]):
            end = index
            break
    return "\n".join(lines[start:end])


def compact(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def resources_by_kind_and_name(resources: list[str], kind: str, name: str) -> list[str]:
    return [
        resource
        for resource in resources
        if top_level_field(resource, "kind") == kind and metadata_field(resource, "name") == name
    ]


def exactly_one(
    resources: list[str],
    kind: str,
    name: str,
    label: str,
    failures: list[str],
) -> str | None:
    matches = resources_by_kind_and_name(resources, kind, name)
    if len(matches) != 1:
        failures.append(f"{label}: expected exactly one {kind}/{name}, found {len(matches)}")
        return None
    return matches[0]
