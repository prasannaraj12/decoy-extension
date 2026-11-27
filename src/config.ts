// Configuration comes from .env (see .env.example). .env is git-ignored.
// Firebase web config values identify the project and are not secrets, but they are still kept out of
// source. Never put a service-account key, or any other real secret, in a VITE_ variable: Vite writes
// them into the bundle.
const clean = (v: string | undefined) => (v && !v.startsWith("YOUR_") ? v.trim() : "");

const values = {
  apiKey: clean(import.meta.env.VITE_FIREBASE_API_KEY),
  authDomain: clean(import.meta.env.VITE_FIREBASE_AUTH_DOMAIN),
  projectId: clean(import.meta.env.VITE_FIREBASE_PROJECT_ID),
  storageBucket: clean(import.meta.env.VITE_FIREBASE_STORAGE_BUCKET),
  messagingSenderId: clean(import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID),
  appId: clean(import.meta.env.VITE_FIREBASE_APP_ID),
};

/** Cloud is refused before any request when this is false. Local analysis does not need Firebase. */
export const FIREBASE_CONFIGURED = !!(values.apiKey && values.projectId && values.appId);
export const FIREBASE_CONFIG = values;

export const RECAPTCHA_ENTERPRISE_SITE_KEY = clean(import.meta.env.VITE_RECAPTCHA_ENTERPRISE_SITE_KEY);

/** Cloud model for redacted, consented escalations. Check the Firebase AI Logic model list. */
export const CLOUD_MODEL = clean(import.meta.env.VITE_CLOUD_MODEL) || "gemini-3.5-flash-lite";

/** true = use an App Check debug token. reCAPTCHA's script cannot load in an extension page (CSP). */
export const APP_CHECK_DEBUG = import.meta.env.VITE_APP_CHECK_DEBUG === "true";
