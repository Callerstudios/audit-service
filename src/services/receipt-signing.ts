import { createPrivateKey, createPublicKey, sign, verify, type KeyObject } from "node:crypto";
import { config } from "../config.js";
import { canonicalJson } from "../lib/crypto.js";

export interface ReceiptSignature {
  algorithm: "Ed25519";
  keyId: string;
  value: string;
}

const privatePem = config.RECEIPT_SIGNING_PRIVATE_KEY.replace(/\\n/g, "\n");
const privateKey = createPrivateKey(privatePem);
if (privateKey.asymmetricKeyType !== "ed25519") {
  throw new Error("RECEIPT_SIGNING_PRIVATE_KEY must be an Ed25519 private key.");
}

const currentPublicPem = createPublicKey(privateKey).export({ type: "spki", format: "pem" }).toString();
const publicKeys = new Map<string, KeyObject>();
for (const [keyId, pem] of Object.entries(config.receiptPublicKeys)) {
  publicKeys.set(keyId, createPublicKey(pem.replace(/\\n/g, "\n")));
}
publicKeys.set(config.RECEIPT_KEY_ID, createPublicKey(currentPublicPem));

export function signReceipt<T extends Record<string, unknown>>(receipt: T): T & { signature: ReceiptSignature } {
  const signature = sign(null, Buffer.from(canonicalJson(receipt)), privateKey).toString("base64url");
  return {
    ...receipt,
    signature: {
      algorithm: "Ed25519",
      keyId: config.RECEIPT_KEY_ID,
      value: signature,
    },
  };
}

export function verifyReceipt(receipt: Record<string, unknown>): boolean {
  const signature = receipt.signature as ReceiptSignature | undefined;
  if (!signature || signature.algorithm !== "Ed25519") return false;
  const key = publicKeys.get(signature.keyId);
  if (!key) return false;

  const { signature: _ignored, ...unsignedReceipt } = receipt;
  try {
    return verify(
      null,
      Buffer.from(canonicalJson(unsignedReceipt)),
      key,
      Buffer.from(signature.value, "base64url"),
    );
  } catch {
    return false;
  }
}

export function getReceiptPublicKeys() {
  const keys = Object.fromEntries(Object.entries(config.receiptPublicKeys));
  keys[config.RECEIPT_KEY_ID] = currentPublicPem;
  return {
    algorithm: "Ed25519" as const,
    currentKeyId: config.RECEIPT_KEY_ID,
    keys,
  };
}
