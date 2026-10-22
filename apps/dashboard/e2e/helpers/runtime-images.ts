import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// The product's default workspace image is the published pin at its public
// mirror, written once in crates/codewire-workspace-image/src/pin.rs: what the
// dashboard offers and what Kind configures as its workspace repository
// (docs/CONFIGURATION.md). Read it from there.
const source = readFileSync(
  path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../crates/codewire-workspace-image/src/pin.rs"),
  "utf8",
);

function publicDefault(family: "workspace"): string {
  const match = source.match(
    new RegExp(`^pub const PUBLIC_IMAGE: &str = "(ghcr\\.io/codewiresh/${family}@sha256:[0-9a-f]{64})";$`, "m"),
  );
  if (!match) throw new Error(`the workspace pin defines no public ${family} default`);
  return match[1];
}

export const defaultWorkspaceImage = publicDefault("workspace");
