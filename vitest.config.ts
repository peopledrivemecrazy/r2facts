import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      main: "./src/index.ts",
      miniflare: {
        compatibilityDate: "2026-08-01",
        r2Buckets: ["BUCKET"],
        bindings: {
          ALLOWED_OWNER_IDS: "1001, 1002",
          AUDIENCE: "r2facts",
          MAX_UPLOAD_BYTES: "1024",
        },
      },
    }),
  ],
});
