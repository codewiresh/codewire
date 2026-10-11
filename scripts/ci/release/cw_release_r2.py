#!/usr/bin/env python3
"""Narrow, immutable Cloudflare R2 publisher for signed cw releases.

The account, bucket, S3 endpoint, public origin and object prefix are fixed.
Immutable objects are created only with `If-None-Match: *`; an existing object
is accepted only after its exact bytes are read back and compared, and is never
deleted or overwritten. An uncertain write is resolved by reading the object
back before any further conditional attempt.

Publication order makes every interruption recoverable: content-addressed
blobs are written and read back first; then one bounded recovery receipt
carrying the exact signed manifest, its signature, SHA256SUMS and the checksum
signature; then those named signed objects, with release.json last. Every
object is read back through the authenticated S3 API. A channel is promoted
only on explicit request, only after the public origin serves every object
exactly, and only through a signed channel object written with the observed
ETag (`If-Match`) or `If-None-Match: *`.

Subcommands:
  probe    print `fresh`, or `retained` after materializing an earlier signed
           publication of this exact tag, source and toolchain so a retry
           reuses its exact signed bytes instead of re-signing
  publish  write and read back the release objects; `--promote stable` also
           moves the stable channel

Diagnostics go to standard error; probe's standard output is only its result.

Credentials come only from a private AWS-style file written by the reviewed
reader; ambient AWS variables are refused. No credential reaches output.
"""

import argparse
import datetime
import hashlib
import hmac
import os
import shutil
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cw_release as release  # noqa: E402

ACCOUNT_ID = "00000000000000000000000000000000"
BUCKET = "codewire-releases"
S3_HOST = f"{ACCOUNT_ID}.r2.cloudflarestorage.com"
REGION = "auto"
PUBLIC_HOST = "releases.codewire.sh"
# The public origin's edge rejects Python's default User-Agent with 403, which
# made every public readback "differ" (release run 12039); name the tool.
PUBLIC_USER_AGENT = "codewire-cw-release/1 (+https://codewire.sh)"
IMMUTABLE_CACHE = "public, max-age=31536000, immutable"
CHANNEL_CACHE = "no-cache"
MAX_OBJECT = release.MAX_EXECUTABLE + 8 * 1024 * 1024
MAX_CREDENTIAL_FILE = 4096
ATTEMPTS = 3
TIMEOUT = 120
RECEIPT = "recovery.json"
SIGNED_NAMES = ("release.json", "release.json.asc", "SHA256SUMS", "SHA256SUMS.asc")
AMBIENT = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE",
           "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE")


class PublishError(Exception):
    pass


class Conflict(PublishError):
    pass


class Uncertain(PublishError):
    pass


class TransportError(Exception):
    """The request's effect is unknown: no response was observed."""


def require(condition, reason, kind=PublishError):
    if not condition:
        raise kind(reason)


class Credentials:
    def __init__(self, access_key_id, secret_access_key):
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key

    def __repr__(self):
        return "Credentials(<redacted>)"


def load_credentials(path, environ=os.environ):
    """Strictly parse the reviewed reader's private AWS credentials file."""
    present = [name for name in AMBIENT if environ.get(name)]
    require(not present, "ambient AWS credential variables are set; refusing fallback")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise PublishError("credential file is not a readable regular file") from None
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= MAX_CREDENTIAL_FILE,
                "credential file must be a private owned single-link 0600 file")
        text = handle.read(MAX_CREDENTIAL_FILE + 1).decode("ascii", errors="strict")
    lines = text.splitlines()
    require(len(lines) == 3 and lines[0] == "[default]" and lines[1].startswith("aws_access_key_id = ")
            and lines[2].startswith("aws_secret_access_key = "), "credential file is not the reviewed format")
    access, secret = lines[1].split(" = ", 1)[1], lines[2].split(" = ", 1)[1]
    require(access.isascii() and access.isalnum() and 16 <= len(access) <= 256
            and secret.isascii() and 32 <= len(secret) <= 512 and " " not in secret,
            "credential file fields are malformed")
    return Credentials(access, secret)


class Response:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = {key.lower(): value for key, value in headers.items()}
        self.body = body


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class HttpsTransport:
    """HTTPS only, no proxies, no redirects, bounded responses."""

    def __init__(self):
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def request(self, method, host, path, headers, body=None, limit=MAX_OBJECT):
        require(host in (S3_HOST, PUBLIC_HOST), "request host is not admitted")
        request = urllib.request.Request(f"https://{host}{path}", data=body, method=method, headers=headers)
        try:
            with self.opener.open(request, timeout=TIMEOUT) as response:
                data = response.read(limit + 1)
                status, response_headers = response.status, dict(response.headers)
        except urllib.error.HTTPError as error:
            data = error.read(limit + 1)
            status, response_headers = error.code, dict(error.headers)
        except (urllib.error.URLError, OSError, TimeoutError) as error:
            raise TransportError(type(error).__name__) from None
        require(len(data) <= limit, "response exceeds its bound")
        return Response(status, response_headers, data)


def _hmac(key, text):
    return hmac.new(key, text.encode(), hashlib.sha256).digest()


def sigv4_headers(credentials, method, host, path, headers, payload_sha256, now, region=REGION):
    """AWS Signature Version 4 for one S3 request (service s3; R2 region auto)."""
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = amz_date[:8]
    signed = {key.lower(): str(value).strip() for key, value in headers.items()}
    signed.update({"host": host, "x-amz-content-sha256": payload_sha256, "x-amz-date": amz_date})
    names = sorted(signed)
    canonical_headers = "".join(f"{name}:{signed[name]}\n" for name in names)
    signed_names = ";".join(names)
    canonical_request = "\n".join([method, path, "", canonical_headers, signed_names, payload_sha256])
    scope = f"{date}/{region}/s3/aws4_request"
    string_to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope,
                                hashlib.sha256(canonical_request.encode()).hexdigest()])
    key = _hmac(_hmac(_hmac(_hmac(("AWS4" + credentials.secret_access_key).encode(), date), region), "s3"),
                "aws4_request")
    signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    result = {name: signed[name] for name in names if name != "host"}
    result["authorization"] = (f"AWS4-HMAC-SHA256 Credential={credentials.access_key_id}/{scope}, "
                               f"SignedHeaders={signed_names}, Signature={signature}")
    return result


def object_path(key):
    require(key.startswith(f"{release.OBJECT_PREFIX}/") and ".." not in key.split("/")
            and all(part for part in key.split("/")), "object key is outside the admitted prefix")
    return "/" + BUCKET + "/" + urllib.parse.quote(key, safe="/-_.~")


class S3:
    def __init__(self, transport, credentials, clock=None):
        self.transport = transport
        self.credentials = credentials
        self.clock = clock or (lambda: datetime.datetime.now(datetime.timezone.utc))

    def _send(self, method, key, body=b"", headers=None, limit=MAX_OBJECT):
        path = object_path(key)
        payload = hashlib.sha256(body).hexdigest()
        signed = sigv4_headers(self.credentials, method, S3_HOST, path, headers or {}, payload, self.clock())
        return self.transport.request(method, S3_HOST, path, signed, body if method == "PUT" else None, limit)

    def get(self, key, limit=MAX_OBJECT):
        return self._send("GET", key, limit=limit)

    def put(self, key, body, content_type, cache_control, condition):
        headers = {"content-type": content_type, "cache-control": cache_control,
                   "content-length": str(len(body))}
        headers.update(condition)
        return self._send("PUT", key, body, headers, limit=64 * 1024)


class PublicOrigin:
    def __init__(self, transport):
        self.transport = transport

    def get(self, key, limit=MAX_OBJECT):
        object_path(key)
        return self.transport.request("GET", PUBLIC_HOST, "/" + urllib.parse.quote(key, safe="/-_.~"),
                                      {"user-agent": PUBLIC_USER_AGENT}, None, limit)


def log(message):
    print(f"cw-release-r2: {message}", file=sys.stderr, flush=True)


def put_immutable(s3, key, data, content_type):
    """Create once; accept an existing object only if its bytes are identical."""
    for _ in range(ATTEMPTS):
        try:
            response = s3.put(key, data, content_type, IMMUTABLE_CACHE, {"if-none-match": "*"})
            if response.status == 200:
                return "created"
            require(response.status in (409, 412) or response.status >= 500,
                    f"{key}: unexpected PUT status {response.status}")
            outcome = "exists" if response.status in (409, 412) else "uncertain"
        except TransportError:
            outcome = "uncertain"
        # Never retry blindly: observe the object first.
        try:
            observed = s3.get(key)
        except TransportError:
            raise Uncertain(f"{key}: write outcome unknown and readback failed") from None
        if observed.status == 200:
            if observed.body == data:
                return "identical" if outcome == "exists" else "created"
            raise Conflict(f"{key}: an existing immutable object has different bytes")
        require(observed.status == 404, f"{key}: unexpected readback status {observed.status}", Uncertain)
    raise Uncertain(f"{key}: object still absent after {ATTEMPTS} conditional attempts")


def immutable_objects(dist):
    """A signed delivery's immutable objects in publication order.

    Content-addressed blobs come first (their count is returned), then the
    recovery receipt, then SHA256SUMS, its signature and the manifest
    signature, with release.json last.
    """
    paths = release.delivery_paths(dist)
    manifest_bytes = release.read_regular(paths["manifest"], release.MAX_JSON)
    manifest = release.validate_manifest(release.parse_canonical(manifest_bytes))
    version = manifest["release_tag"]
    objects, seen = [], set()

    def add(ref, data, content_type):
        require(ref["sha256"] == release.sha256(data) and ref["size"] == len(data),
                f"{ref['key']}: local bytes differ from the manifest")
        if ref["key"] not in seen:
            seen.add(ref["key"])
            objects.append((ref["key"], data, content_type))

    for entry in manifest["targets"]:
        add(entry["executable"], release.read_regular(Path(dist) / entry["asset_name"], release.MAX_EXECUTABLE),
            "application/octet-stream")
        if entry["target"] == release.RUNTIME_TARGET:
            add(entry["oci"]["archive"], release.read_regular(paths["oci"], MAX_OBJECT), "application/x-tar")
            add(entry["runtime_pack"], release.read_regular(paths["pack"], MAX_OBJECT), "application/octet-stream")
            add(entry["runtime_lock"], release.read_regular(paths["lock"], release.MAX_JSON), "application/json")
    blobs = len(objects)
    sums = release.read_regular(paths["sums"], release.MAX_JSON)
    sums_sig = release.read_regular(paths["sums_sig"], release.MAX_SIGNATURE)
    signature = release.read_regular(paths["manifest_sig"], release.MAX_SIGNATURE)
    receipt = release.recovery_receipt(version, manifest_bytes, signature, sums, sums_sig)
    add(release.object_ref(release.release_key(version, RECEIPT), receipt), receipt, "application/json")
    add(manifest["checksums"]["file"], sums, "text/plain")
    add(manifest["checksums"]["signature"], sums_sig, "application/pgp-signature")
    add(release.object_ref(release.release_key(version, "release.json.asc"), signature), signature,
        "application/pgp-signature")
    add(release.object_ref(release.release_key(version, "release.json"), manifest_bytes), manifest_bytes,
        "application/json")
    return version, manifest_bytes, objects, blobs


def read_back(reader, objects, label):
    for key, data, _ in objects:
        try:
            observed = reader.get(key)
        except TransportError:
            raise PublishError(f"{key}: {label} readback failed") from None
        require(observed.status == 200 and observed.body == data, f"{key}: {label} readback differs")
    log(f"{label} readback objects={len(objects)} exact=true")


def probe(s3, dist, version, retain_into, trust):
    """Decide whether this run publishes fresh or retains an earlier signature.

    A committed release.json or a recovery receipt is materialized with its
    exact signed bytes, but only when it was built from this run's exact tag,
    source and toolchain. Named signed objects without either are an
    incomplete publication and are refused, never reused or overwritten.
    """
    candidate = release.prepared_candidate(dist)
    require(candidate["version"] == version, "prepared delivery is for a different release")

    def observe(name, limit):
        try:
            response = s3.get(release.release_key(version, name), limit)
        except TransportError:
            raise PublishError(f"release probe of {name} failed; outcome unknown") from None
        require(response.status in (200, 404), f"release probe of {name} returned status {response.status}")
        return response.body if response.status == 200 else None

    limits = {"release.json": release.MAX_JSON, "release.json.asc": release.MAX_SIGNATURE,
              "SHA256SUMS": release.MAX_JSON, "SHA256SUMS.asc": release.MAX_SIGNATURE}
    named = {name: observe(name, limits[name]) for name in SIGNED_NAMES}
    receipt = observe(RECEIPT, release.MAX_RECOVERY)
    if named["release.json"] is None and receipt is None:
        require(all(data is None for data in named.values()),
                "signed release objects exist without a recovery receipt or committed manifest; "
                "the publication is incomplete and is neither reused nor overwritten", Conflict)
        log(f"probe release={version} state=fresh")
        return "fresh"
    try:
        if receipt is not None:
            signed, manifest = release.open_recovery_receipt(receipt, version, trust)
        else:
            require(all(data is not None for data in named.values()),
                    "committed release is missing a signed object", Conflict)
            signed = tuple(named[name] for name in SIGNED_NAMES)
            manifest = release.check_signed_release(version, *signed, trust)
        recovered = dict(zip(SIGNED_NAMES, signed))
        for name, data in named.items():
            require(data is None or data == recovered[name],
                    f"published {name} contradicts the recovered signed release", Conflict)
        release.require_same_source(manifest, candidate)
    except release.ReleaseError as error:
        raise Conflict(f"published release is not reusable: {error}") from None
    root = Path(retain_into)
    require(not root.exists(), "retain directory already exists")
    try:
        materialize(s3, root, manifest, *signed)
    except BaseException:
        shutil.rmtree(root, ignore_errors=True)  # Only this probe created it.
        raise
    log(f"probe release={version} state=retained objects_verified=true")
    return "retained"


def materialize(s3, root, manifest, manifest_bytes, signature, sums, sums_sig):
    """Write the published release's exact bytes as a delivery directory."""
    paths = release.delivery_paths(root)
    for directory in (root, root / release.DELIVERY, paths["identities"], paths["oci"].parent,
                      paths["pointer"].parent):
        directory.mkdir(mode=0o755)

    def fetch(ref, limit=MAX_OBJECT):
        try:
            response = s3.get(ref["key"], limit)
        except TransportError:
            raise PublishError(f"{ref['key']}: readback failed; outcome unknown") from None
        require(response.status == 200 and release.sha256(response.body) == ref["sha256"]
                and len(response.body) == ref["size"], f"{ref['key']}: published object is missing or differs",
                Conflict)
        return response.body

    for entry in manifest["targets"]:
        release.write_new(root / entry["asset_name"], fetch(entry["executable"]), 0o755)
        release.write_new(paths["identities"] / f"{entry['target']}.json", release.canonical(entry["identity"]))
        if entry["target"] == release.RUNTIME_TARGET:
            oci = entry["oci"]
            release.write_new(paths["oci"], fetch(oci["archive"]))
            release.write_new(paths["pack"], fetch(entry["runtime_pack"]))
            release.write_new(paths["lock"], fetch(entry["runtime_lock"], release.MAX_JSON))
            release.write_new(paths["image"], release.canonical({
                "schema_version": 1, "index_sha256": oci["index_sha256"],
                "manifest_sha256": oci["manifest_sha256"], "archive_sha256": oci["archive"]["sha256"],
                "cw_sha256": entry["identity"]["sha256"], "source_revision": manifest["source_revision"]}))
    release.write_new(paths["sums"], sums)
    release.write_new(paths["sums_sig"], sums_sig)
    release.write_new(paths["manifest"], manifest_bytes)
    release.write_new(paths["manifest_sig"], signature)
    try:
        # Re-derive every identity from the retained bytes and build records.
        release.verify_delivery(root)
    except (release.ReleaseError, subprocess.CalledProcessError) as error:
        raise Conflict(f"retained release does not verify: {error}") from None


def promote(s3, origin, objects, channel_bytes, version, trust):
    """Move one channel by compare-and-swap after exact public readback.

    Channels are compared by their verified complete pointer, so a retry whose
    pointer was re-signed with different signature bytes is unchanged.
    """
    pointer = release.verify_channel(channel_bytes, trust)
    require(pointer["release_tag"] == version, "channel object does not point at this release")
    read_back(origin, objects, "public")
    key = release.channel_key(pointer["channel"])
    unchanged = f"promote channel={pointer['channel']} release={version} state=unchanged"

    def names_this_pointer(data):
        try:
            return release.verify_channel(data, trust) == pointer
        except release.ReleaseError:
            return False

    try:
        current = s3.get(key, release.MAX_JSON)
    except TransportError:
        raise PublishError("channel read failed; promotion not attempted") from None
    if current.status == 404:
        condition, previous = {"if-none-match": "*"}, None
    else:
        require(current.status == 200 and current.headers.get("etag"), "channel read returned no ETag")
        existing = release.verify_channel(current.body, trust)
        if existing == pointer:
            log(unchanged)
            return "unchanged"
        require(release.version_key(existing["release_tag"]) < release.version_key(version),
                "channel already points at the same or a newer release", Conflict)
        condition, previous = {"if-match": current.headers["etag"]}, current.body
    for _ in range(2):
        try:
            response = s3.put(key, channel_bytes, "application/json", CHANNEL_CACHE, condition)
            if response.status == 200:
                break
            require(response.status == 412 or response.status >= 500, f"channel PUT status {response.status}")
            stale = response.status == 412
        except TransportError:
            stale = False
        # A lost race or unknown outcome is observed before deciding; the
        # write is never retried unconditionally.
        try:
            observed = s3.get(key, release.MAX_JSON)
        except TransportError:
            raise Uncertain("channel promotion outcome unknown and readback failed") from None
        if observed.status == 200 and observed.body == channel_bytes:
            break
        if observed.status == 200 and names_this_pointer(observed.body):
            log(unchanged)
            return "unchanged"
        require(not stale, "channel changed since it was read (stale ETag)", Conflict)
        intact = (observed.status == 404 and previous is None) or \
                 (observed.status == 200 and observed.body == previous and
                  observed.headers.get("etag") == condition.get("if-match"))
        require(intact, "channel changed during an uncertain promotion", Conflict)
    else:
        raise Uncertain("channel promotion did not complete")
    observed = s3.get(key, release.MAX_JSON)
    require(observed.status == 200 and observed.body == channel_bytes, "channel readback differs")
    log(f"promote channel={pointer['channel']} release={version} state=promoted")
    return "promoted"


def publish(s3, origin, dist, trust, promote_channel=None):
    version, _, objects, blobs = immutable_objects(dist)
    release.verify_delivery(dist, trust)
    counts = {"created": 0, "identical": 0}

    def put(batch):
        for key, data, content_type in batch:
            try:
                outcome = put_immutable(s3, key, data, content_type)
            except Conflict:
                if key.endswith("/" + RECEIPT):
                    raise Conflict("another publication recorded different signed bytes for this release; "
                                   "rerun to probe and retain them") from None
                raise
            counts[outcome] += 1
            log(f"object {key} {outcome}")

    put(objects[:blobs])
    read_back(s3, objects[:blobs], "authenticated blob")
    put(objects[blobs:])
    read_back(s3, objects, "authenticated")
    log(f"release={version} objects={len(objects)} created={counts['created']} identical={counts['identical']}")
    if promote_channel is None:
        log("promotion=none")
        return counts, "none"
    require(promote_channel in release.CHANNELS, "channel is not admitted")
    channel_bytes = release.read_regular(release.delivery_paths(dist)["channel"], release.MAX_JSON)
    return counts, promote(s3, origin, objects, channel_bytes, version, trust)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    probe_parser = sub.add_parser("probe")
    probe_parser.add_argument("--dist", type=Path, required=True)
    probe_parser.add_argument("--version", required=True)
    probe_parser.add_argument("--retain-into", type=Path, required=True)
    probe_parser.add_argument("--credentials", type=Path, required=True)
    publish_parser = sub.add_parser("publish")
    publish_parser.add_argument("--dist", type=Path, required=True)
    publish_parser.add_argument("--credentials", type=Path, required=True)
    publish_parser.add_argument("--promote", choices=("none",) + release.CHANNELS, default="none")
    args = parser.parse_args(argv)
    try:
        transport = HttpsTransport()
        s3 = S3(transport, load_credentials(args.credentials))
        if args.command == "probe":
            require(release.release_version(args.version), "release version is invalid")
            print(probe(s3, args.dist, args.version, args.retain_into, release.PRODUCTION_TRUST))
        else:
            publish(s3, PublicOrigin(transport), args.dist, release.PRODUCTION_TRUST,
                    None if args.promote == "none" else args.promote)
    except (PublishError, release.ReleaseError) as error:
        print(f"cw-release-r2: REJECT {type(error).__name__}: {error}", file=sys.stderr)
        return 3 if isinstance(error, Uncertain) else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
