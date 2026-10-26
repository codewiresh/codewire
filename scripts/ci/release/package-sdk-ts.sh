#!/usr/bin/env bash
# Pack the TypeScript SDK (@codewire/sdk) as one self-contained npm tarball.
#
# usage: package-sdk-ts.sh OUTDIR
#
# The SDK imports its Connect-RPC schemas from the private workspace package
# @codewire/proto-ts, which holds TypeScript sources whose relative imports
# carry no extension. Neither loads in plain Node. This script compiles only
# the public schemas the SDK reaches (codewire/v1, codewire/bridge and
# google/rpc) to JavaScript and declarations, gives every relative import its
# .js extension, and bundles the result inside the SDK's tarball, so
# `npm install @codewire/sdk` needs nothing that is not on npm. It then
# installs the tarball into an empty project and imports it with plain Node
# and type-checks a consumer, so a tarball that would not load is never
# written to OUTDIR.
set -euo pipefail

fail() {
  printf '[package-sdk-ts] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 ]] || {
  printf 'usage: package-sdk-ts.sh OUTDIR\n' >&2
  exit 2
}
root="$(cd "$(dirname "$0")/../../.." && pwd)"
mkdir -p "$1"
outdir="$(cd "$1" && pwd)"
sdk="$root/libs/sdk-ts"
proto="$root/packages/codewire-proto-ts"

work="$(mktemp -d "${TMPDIR:-/tmp}/codewire-sdk-ts-package.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT

version="$(node -p 'require(process.argv[1]).version' "$sdk/package.json")"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "SDK version is not MAJOR.MINOR.PATCH: $version"

(cd "$sdk" && npm ci --silent --install-links --ignore-scripts --no-audit --no-fund && rm -rf dist && npm run --silent build)
tsc="$sdk/node_modules/.bin/tsc"

# The public schemas only; admin, console, internal and testing never ship.
mkdir -p "$work/proto/src/gen/codewire" "$work/proto/src/gen/google"
cp "$proto/src/index.ts" "$work/proto/src/"
cp -R "$proto/src/gen/codewire/v1" "$proto/src/gen/codewire/bridge" "$work/proto/src/gen/codewire/"
cp -R "$proto/src/gen/google/rpc" "$work/proto/src/gen/google/"
cat >"$work/proto/tsconfig.json" <<'JSON'
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "declaration": true,
    "outDir": "dist",
    "rootDir": "src",
    "strict": true,
    "skipLibCheck": true,
    "typeRoots": [],
    "baseUrl": "."
  },
  "include": ["src"]
}
JSON
ln -s "$sdk/node_modules" "$work/proto/node_modules"
(cd "$work/proto" && "$tsc" -p tsconfig.json)
rm "$work/proto/node_modules"

# protoc-gen-es writes `from "./common_pb"`; Node's ESM loader needs the file.
node - "$work/proto/dist" <<'JS'
const fs = require("node:fs");
const path = require("node:path");
const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
  entry.isDirectory() ? walk(path.join(dir, entry.name)) : [path.join(dir, entry.name)]);
const relative = /((?:from|import)\s*\(?\s*["'])(\.\.?\/[^"']+?)(["'])/g;
for (const file of walk(process.argv[2])) {
  if (!/\.(js|d\.ts)$/.test(file)) continue;
  const text = fs.readFileSync(file, "utf8").replace(relative, (match, open, spec, close) => {
    if (spec.endsWith(".js")) return match;
    const target = path.resolve(path.dirname(file), spec);
    if (!fs.existsSync(`${target}.js`)) throw new Error(`${file}: ${spec} has no compiled module`);
    return `${open}${spec}.js${close}`;
  });
  fs.writeFileSync(file, text);
}
JS

package="$work/package"
bundled="$package/node_modules/@codewire/proto-ts"
mkdir -p "$bundled"
cp -R "$sdk/dist" "$sdk/LICENSE" "$sdk/README.md" "$package/"
# The SDK's own tests compile beside it; they are not part of the package.
find "$package/dist" -type f \( -name '*.test.*' -o -name 'test.*' -o -name 'e2e.*' \) -delete
cp -R "$work/proto/dist" "$proto/LICENSE" "$proto/LICENSE-APACHE" "$bundled/"

node - "$sdk/package.json" "$proto/package.json" "$package/package.json" "$bundled/package.json" "$version" <<'JS'
const fs = require("node:fs");
const [sdkPath, protoPath, packagePath, bundledPath, version] = process.argv.slice(2);
const sdk = JSON.parse(fs.readFileSync(sdkPath, "utf8"));
const proto = JSON.parse(fs.readFileSync(protoPath, "utf8"));
const runtime = proto.dependencies["@bufbuild/protobuf"];
if (sdk.dependencies["@bufbuild/protobuf"] !== runtime) {
  throw new Error("the SDK and its schemas pin different @bufbuild/protobuf versions");
}
const subpath = (dir) => ({ types: `./dist/gen/${dir}/*.d.ts`, import: `./dist/gen/${dir}/*.js` });
fs.writeFileSync(bundledPath, `${JSON.stringify({
  name: proto.name,
  version,
  description: "Connect-RPC schemas bundled with @codewire/sdk",
  license: proto.license,
  type: "module",
  exports: {
    ".": { types: "./dist/index.d.ts", import: "./dist/index.js" },
    "./gen/codewire/v1/*": subpath("codewire/v1"),
    "./gen/codewire/bridge/v1/*": subpath("codewire/bridge/v1"),
    "./gen/google/rpc/*": subpath("google/rpc"),
  },
  dependencies: { "@bufbuild/protobuf": runtime },
}, null, 2)}\n`);
const published = { ...sdk };
delete published.scripts;
delete published.devDependencies;
published.files = ["dist", "README.md"];
published.dependencies = { ...sdk.dependencies, "@codewire/proto-ts": version };
published.bundleDependencies = ["@codewire/proto-ts"];
fs.writeFileSync(packagePath, `${JSON.stringify(published, null, 2)}\n`);
JS

(cd "$package" && npm pack --silent --pack-destination "$work" >/dev/null)
tarball="$work/codewire-sdk-$version.tgz"
[[ -f "$tarball" ]] || fail "npm pack wrote no codewire-sdk-$version.tgz"
tar -tzf "$tarball" >"$work/contents"
if grep -E '/gen/codewire/(admin|console|internal|testing)/|\.test\.|/dist/(test|e2e)\.' "$work/contents"; then
  fail 'the tarball carries a private schema package or a test'
fi
grep -qx 'package/node_modules/@codewire/proto-ts/dist/index.js' "$work/contents" ||
  fail 'the tarball does not bundle the compiled schemas'

# A consumer that has only npm: plain Node loads it and TypeScript checks it.
consumer="$work/consumer"
mkdir -p "$consumer"
printf '{"name":"consumer","private":true,"type":"module"}\n' >"$consumer/package.json"
(cd "$consumer" && npm install --silent --ignore-scripts --no-audit --no-fund "$tarball")
# shellcheck disable=SC2016 # the module source is JavaScript, not shell.
(cd "$consumer" && node --input-type=module -e '
const sdk = await import("@codewire/sdk");
for (const name of ["Codewire", "CodewireError", "Environment"]) {
  if (typeof sdk[name] !== "function") throw new Error(`@codewire/sdk exports no ${name}`);
}
new sdk.Codewire({ apiKey: "cw_example", baseUrl: "https://codewire.example" });
')
cat >"$consumer/consumer.ts" <<'TS'
import { Codewire, CodewireError } from "@codewire/sdk";
export const client: Codewire = new Codewire({ apiKey: "cw_example" });
export const isError = (value: unknown): value is CodewireError => value instanceof CodewireError;
TS
"$tsc" --noEmit --strict --module nodenext --moduleResolution nodenext --target ES2022 \
  --skipLibCheck --types node --typeRoots "$sdk/node_modules/@types" "$consumer/consumer.ts"

cp "$tarball" "$outdir/"
printf '[package-sdk-ts] wrote %s\n' "$outdir/codewire-sdk-$version.tgz"
