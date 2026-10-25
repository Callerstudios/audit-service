import { z } from "zod";

const identifier = z.string().trim().min(1).max(160);
const namePattern = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;

const participantSchema = z.object({
  type: identifier,
  id: identifier,
}).strict();

const eventSchema = z.object({
  eventId: identifier,
  eventType: z.string().min(3).max(120).regex(namePattern),
  occurredAt: z.iso.datetime({ offset: true }),
  correlationId: identifier.optional(),
  actor: participantSchema.optional(),
  target: participantSchema.optional(),
  outcome: z.enum(["success", "failure", "denied", "unknown"]),
  reasonCode: z.string().max(120).regex(/^[A-Z0-9_]+$/).optional(),
  metadata: z.record(z.string().max(100), z.unknown()).optional(),
}).strict();

export const ingestRequestSchema = z.object({
  schemaVersion: z.literal(1),
  batchId: identifier,
  events: z.array(eventSchema).min(1).max(400),
}).strict();

export type AuditEventInput = z.infer<typeof eventSchema>;
export type IngestRequest = z.infer<typeof ingestRequestSchema>;

const sensitiveKey = /(password|secret|token|cookie|authorization|credential|private.?key|recovery.?code|session.?id)/i;

function containsSensitiveKey(value: unknown, depth = 0): boolean {
  if (depth > 8) return true;
  if (Array.isArray(value)) return value.some((item) => containsSensitiveKey(item, depth + 1));
  if (value === null || typeof value !== "object") return false;
  return Object.entries(value).some(([key, child]) => sensitiveKey.test(key) || containsSensitiveKey(child, depth + 1));
}

export function validateIngestBody(value: unknown, maxEvents: number): IngestRequest {
  const schema = ingestRequestSchema.extend({ events: z.array(eventSchema).min(1).max(maxEvents) });
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    throw new Error(`Invalid event payload: ${z.prettifyError(parsed.error)}`);
  }

  const eventIds = parsed.data.events.map((event) => event.eventId);
  if (new Set(eventIds).size !== eventIds.length) {
    throw new Error("Each eventId must be unique within its batch.");
  }
  if (containsSensitiveKey(parsed.data)) {
    throw new Error("Metadata contains a key that is not allowed in audit records.");
  }
  return parsed.data;
}
