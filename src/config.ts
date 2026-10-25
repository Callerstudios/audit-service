import "dotenv/config";
import { z } from "zod";

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().min(1).max(65535).default(4000),
  FIREBASE_PROJECT_ID: z.string().min(1),
  FIREBASE_KEY: z.string().optional(),
  PRODUCER_KEYS_JSON: z.string().min(1),
  REVIEWER_KEYS_JSON: z.string().default("{}"),
  RECEIPT_KEY_ID: z.string().min(1).default("receipt-key-1"),
  RECEIPT_SIGNING_PRIVATE_KEY: z.string().min(1),
  RECEIPT_PUBLIC_KEYS_JSON: z.string().default("{}"),
  MAX_EVENTS_PER_BATCH: z.coerce.number().int().min(1).max(400).default(100),
  MAX_EVENT_BODY_BYTES: z.coerce.number().int().min(1024).max(1_048_576).default(262_144),
  AUTH_CLOCK_SKEW_SECONDS: z.coerce.number().int().min(30).max(900).default(300),
  NONCE_TTL_SECONDS: z.coerce.number().int().min(600).max(86_400).default(900),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().int().min(1000).default(60_000),
  RATE_LIMIT_MAX: z.coerce.number().int().min(1).default(120),
});

const parsed = envSchema.safeParse(process.env);
if (!parsed.success) {
  throw new Error(`Invalid environment configuration: ${z.prettifyError(parsed.error)}`);
}

const keysSchema = z.record(z.string().min(1), z.record(z.string().min(1), z.string().min(32)));
const parsedKeys = keysSchema.safeParse(JSON.parse(parsed.data.PRODUCER_KEYS_JSON));
if (!parsedKeys.success || Object.keys(parsedKeys.data).length === 0) {
  throw new Error("PRODUCER_KEYS_JSON must map producer IDs to key IDs and secrets of at least 32 characters.");
}

const parsedReviewKeys = keysSchema.safeParse(JSON.parse(parsed.data.REVIEWER_KEYS_JSON));
if (!parsedReviewKeys.success) {
  throw new Error("REVIEWER_KEYS_JSON must map reviewer IDs to key IDs and secrets of at least 32 characters.");
}

const publicKeysSchema = z.record(z.string().min(1), z.string().min(1));
const parsedPublicKeys = publicKeysSchema.safeParse(JSON.parse(parsed.data.RECEIPT_PUBLIC_KEYS_JSON));
if (!parsedPublicKeys.success) {
  throw new Error("RECEIPT_PUBLIC_KEYS_JSON must map receipt key IDs to PEM-encoded public keys.");
}

export const config = {
  ...parsed.data,
  producerKeys: parsedKeys.data,
  reviewerKeys: parsedReviewKeys.data,
  receiptPublicKeys: parsedPublicKeys.data,
};

export type ProducerId = keyof typeof config.producerKeys;
