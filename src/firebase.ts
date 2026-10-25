import { applicationDefault, cert, getApps, initializeApp } from "firebase-admin/app";
import { getFirestore } from "firebase-admin/firestore";
import { config } from "./config.js";

function getCredential() {
  if (!config.FIREBASE_KEY) return applicationDefault();

  let serviceAccount: Record<string, unknown>;
  try {
    serviceAccount = JSON.parse(config.FIREBASE_KEY) as Record<string, unknown>;
  } catch {
    throw new Error("FIREBASE_KEY must contain valid service-account JSON.");
  }

  if (serviceAccount.type !== "service_account") {
    throw new Error("FIREBASE_KEY must be a service-account JSON credential.");
  }

  const projectId = serviceAccount.project_id;
  const clientEmail = serviceAccount.client_email;
  const privateKey = serviceAccount.private_key;
  if (typeof projectId !== "string" || typeof clientEmail !== "string" || typeof privateKey !== "string") {
    throw new Error("FIREBASE_KEY is missing project_id, client_email, or private_key.");
  }

  return cert({
    projectId,
    clientEmail,
    privateKey: privateKey.replace(/\\n/g, "\n"),
  });
}

const app = getApps()[0] ?? initializeApp({
  credential: getCredential(),
  projectId: config.FIREBASE_PROJECT_ID,
});

export const db = getFirestore(app);
