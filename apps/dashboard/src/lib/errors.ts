import { ConnectError } from "@connectrpc/connect";
import { BadRequestSchema, RetryInfoSchema } from "@codewire/proto-ts";

export type FieldViolation = {
  field: string;
  description: string;
};

export function errorMessage(error: unknown): string {
  if (error instanceof ConnectError) return error.rawMessage;
  if (error instanceof Error) return error.message;
  return "Request failed";
}

export function fieldViolations(error: unknown): FieldViolation[] {
  if (!(error instanceof ConnectError)) return [];

  return error.findDetails(BadRequestSchema).flatMap((detail) =>
    detail.fieldViolations.map(({ field, description }) => ({
      field,
      description,
    })),
  );
}

export function retryDelay(error: unknown): number | undefined {
  if (!(error instanceof ConnectError)) return undefined;

  const delay = error.findDetails(RetryInfoSchema)[0]?.retryDelay;
  if (!delay) return undefined;

  return Number(delay.seconds) * 1_000 + delay.nanos / 1_000_000;
}
