import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Standalone output → small, self-contained runtime image for Docker.
  output: "standalone",
  // Don't advertise the framework (drops the X-Powered-By: Next.js header).
  poweredByHeader: false,
};

export default nextConfig;
