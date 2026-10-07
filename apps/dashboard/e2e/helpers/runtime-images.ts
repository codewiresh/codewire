import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// The product's default runtime images are written once, in
// crates/codewire-server-core/src/runtime_images.rs. Read them from there.
const source = readFileSync(
  path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../crates/codewire-server-core/src/runtime_images.rs"),
  "utf8",
);

function harborDefault(family: "workspace"): string {
  const match = source.match(new RegExp(`"(registry\\.example\\.invalid/codewire/${family}@sha256:[0-9a-f]{64})"`));
  if (!match) throw new Error(`runtime_images.rs defines no ${family} default`);
  return match[1];
}

export const defaultWorkspaceImage = harborDefault("workspace");
