import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// The product's default workspace image is the published pin, written once in
// crates/codewire-workspace-image/src/pin.rs. Read it from there.
const source = readFileSync(
  path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../crates/codewire-workspace-image/src/pin.rs"),
  "utf8",
);

function harborDefault(family: "workspace"): string {
  const match = source.match(new RegExp(`"(registry\\.example\\.invalid/codewire/${family}@sha256:[0-9a-f]{64})"`));
  if (!match) throw new Error(`the workspace pin defines no ${family} default`);
  return match[1];
}

export const defaultWorkspaceImage = harborDefault("workspace");
