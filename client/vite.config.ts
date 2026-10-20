import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import fs from "node:fs";
import path from "node:path";
import https from "node:https";

// Dev proxy: /api -> https://localhost:8000. The API requires mTLS, so present the nginx client cert when available.
const certDir = path.resolve(__dirname, "../infra/certs");
const certFile = path.join(certDir, "nginx-client.crt");
const keyFile = path.join(certDir, "nginx-client.key");
const caFile = path.join(certDir, "internal-ca.crt");
const haveMtls = fs.existsSync(certFile) && fs.existsSync(keyFile);
const agent = haveMtls
  ? new https.Agent({
      cert: fs.readFileSync(certFile),
      key: fs.readFileSync(keyFile),
      ca: fs.existsSync(caFile) ? fs.readFileSync(caFile) : undefined,
      rejectUnauthorized: false,
      keepAlive: true,
    })
  : undefined;

export default defineConfig({
  plugins: [react()],
  worker: { format: "es" },
  build: { target: "es2022", sourcemap: false },
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "https://localhost:8000",
        secure: false,
        xfwd: true,
        changeOrigin: false,
        agent,
      },
    },
  },
  // vitest
  test: { environment: "node", include: ["src/**/*.test.ts"] },
} as Parameters<typeof defineConfig>[0]);
