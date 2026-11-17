const configuredApiUrl = import.meta.env.VITE_API_URL?.trim().replace(/\/+$/, "");

if (!configuredApiUrl) {
  throw new Error(
    "VITE_API_URL is not set. Create frontend/.env from .env.example."
  );
}

export const API_BASE_URL = configuredApiUrl;
