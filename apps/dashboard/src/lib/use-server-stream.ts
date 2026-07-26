import { useCallback, useEffect, useRef } from "react";

type StreamFactory<T> = (signal: AbortSignal) => AsyncIterable<T>;

export type StreamReconnect = {
  initialDelayMs?: number;
  maxDelayMs?: number;
  maxAttempts?: number;
};

type ServerStreamOptions<T> = {
  stream: StreamFactory<T>;
  onMessage: (message: T) => void;
  onError: (error: unknown) => void;
  reconnect?: StreamReconnect;
};

const DEFAULT_INITIAL_DELAY_MS = 250;
const DEFAULT_MAX_DELAY_MS = 10_000;
const DEFAULT_MAX_ATTEMPTS = 8;

function isAbortError(error: unknown, signal: AbortSignal): boolean {
  return signal.aborted || (error instanceof DOMException && error.name === "AbortError") ||
    (error instanceof Error && error.name === "AbortError");
}

function waitForRetry(delayMs: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = window.setTimeout(() => {
      signal.removeEventListener("abort", abort);
      resolve();
    }, delayMs);
    const abort = () => {
      window.clearTimeout(timer);
      signal.removeEventListener("abort", abort);
      reject(new DOMException("The operation was aborted", "AbortError"));
    };
    signal.addEventListener("abort", abort, { once: true });
  });
}

/**
 * Runs one browser server stream at a time. Watch-style flows deliberately
 * finish at EOF; long-lived Stream-style consumers opt into bounded retries.
 */
export function useServerStream<T>() {
  const controllerRef = useRef<AbortController | null>(null);

  const abort = useCallback(() => {
    controllerRef.current?.abort();
  }, []);

  useEffect(() => abort, [abort]);

  const run = useCallback((options: ServerStreamOptions<T>) => {
    abort();

    const controller = new AbortController();
    controllerRef.current = controller;

    void (async () => {
      const reconnect = options.reconnect;
      const initialDelayMs = reconnect?.initialDelayMs ?? DEFAULT_INITIAL_DELAY_MS;
      const maxDelayMs = reconnect?.maxDelayMs ?? DEFAULT_MAX_DELAY_MS;
      const maxAttempts = reconnect?.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
      let attempts = 0;

      try {
        for (;;) {
          try {
            for await (const message of options.stream(controller.signal)) {
              attempts = 0;
              if (controller.signal.aborted) return;
              options.onMessage(message);
            }
            return;
          } catch (error) {
            if (isAbortError(error, controller.signal)) return;
            if (!reconnect || attempts >= maxAttempts) {
              options.onError(error);
              return;
            }

            const cappedDelay = Math.min(
              maxDelayMs,
              initialDelayMs * 2 ** attempts,
            );
            attempts += 1;
            // Full jitter prevents a fleet of long-lived feeds reconnecting together.
            await waitForRetry(Math.floor(Math.random() * (cappedDelay + 1)), controller.signal);
          }
        }
      } finally {
        if (controllerRef.current === controller) controllerRef.current = null;
      }
    })();
  }, [abort]);

  return { abort, run };
}
