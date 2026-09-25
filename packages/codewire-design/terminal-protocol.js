(() => {
  "use strict";

  const protocol = "codewire.durable-terminal.v1";
  const limits = Object.freeze({ frameBytes: 65536, inputBytes: 16384, outputChunkBytes: 32768,
    unacknowledgedOutputBytes: 262144, unacknowledgedOutputFrames: 64, pendingInputFrames: 64, pendingInputBytes: 262144 });
  const states = Object.freeze(["starting", "running", "stopping", "stopped", "exited", "failed", "interrupted"]);
  const encoder = new TextEncoder();
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  const sessionId = (value) => typeof value === "string" && value.startsWith("session-") && uuid.test(value.slice(8));
  // Account and organization IDs are opaque (currently 32 hex bytes), not UUIDs.
  const accountId = (value) => typeof value === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(value);
  const organizationId = accountId;
  const bytes = (value) => encoder.encode(value).length;
  const closed = (value, required, optional = []) => value !== null && typeof value === "object"
    && !Array.isArray(value) && required.every((key) => Object.hasOwn(value, key))
    && Object.keys(value).every((key) => required.includes(key) || optional.includes(key));
  const reject = () => { throw new Error("Invalid terminal frame"); };

  function offset(value) {
    if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,19})$/.test(value)) return reject();
    const result = BigInt(value);
    if (result > 18446744073709551615n) return reject();
    return result;
  }

  function encodeClient(frame) {
    if (frame?.type === "input" && closed(frame, ["type", "data"])) {
      if (typeof frame.data !== "string" || !frame.data.length || !frame.data.isWellFormed()
        || bytes(frame.data) > limits.inputBytes) return reject();
    } else if (frame?.type === "resize" && closed(frame, ["type", "columns", "rows"])) {
      if (![frame.columns, frame.rows].every((size) => Number.isInteger(size) && size >= 1 && size <= 65535)) return reject();
    } else if (frame?.type === "ack" && closed(frame, ["type", "offset"])) {
      offset(frame.offset);
    } else return reject();
    const encoded = JSON.stringify(frame);
    if (bytes(encoded) > limits.frameBytes) return reject();
    return encoded;
  }

  function decodeServer(encoded) {
    if (typeof encoded !== "string" || encoded.length > limits.frameBytes || bytes(encoded) > limits.frameBytes) return reject();
    const frame = JSON.parse(encoded);
    if (frame?.type === "status" && closed(frame, ["type", "state"], ["exitCode"])) {
      if (!states.includes(frame.state) || (Object.hasOwn(frame, "exitCode")
        && (["starting", "running", "stopping"].includes(frame.state)
          || !Number.isInteger(frame.exitCode) || frame.exitCode < -2147483648 || frame.exitCode > 2147483647))) return reject();
      return frame;
    }
    if (frame?.type === "historyGap" && closed(frame, ["type", "requestedOffset", "retainedStartOffset"])) {
      const requested = offset(frame.requestedOffset);
      const retained = offset(frame.retainedStartOffset);
      if (retained <= requested) return reject();
      return { type: "historyGap", requestedOffset: requested, retainedStartOffset: retained };
    }
    if (frame?.type !== "output" || !closed(frame, ["type", "offset", "nextOffset", "data"])) return reject();
    const start = offset(frame.offset);
    const next = offset(frame.nextOffset);
    if (typeof frame.data !== "string" || frame.data.length > 4 * Math.ceil(limits.outputChunkBytes / 3)
      || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(frame.data)) return reject();
    const decoded = atob(frame.data);
    if (!decoded.length || decoded.length > limits.outputChunkBytes || btoa(decoded) !== frame.data
      || next !== start + BigInt(decoded.length)) return reject();
    return { type: "output", offset: start, nextOffset: next, data: Uint8Array.from(decoded, (char) => char.charCodeAt(0)) };
  }

  function session(value) {
    if (!closed(value, ["sessionId", "state"]) || !sessionId(value.sessionId) || !states.includes(value.state)) return reject();
    return value;
  }

  function inventory(value) {
    if (!closed(value, ["accountId", "sessions"]) || !accountId(value.accountId)
      || !Array.isArray(value.sessions) || value.sessions.length > 256) return reject();
    const seen = new Set();
    for (const item of value.sessions) {
      session(item);
      if (seen.has(item.sessionId)) return reject();
      seen.add(item.sessionId);
    }
    return value;
  }

  globalThis.CodewireTerminalProtocol = Object.freeze({ protocol, limits, states, uuid, sessionId,
    accountId, organizationId, bytes, closed, offset, encodeClient, decodeServer, session, inventory });
})();
