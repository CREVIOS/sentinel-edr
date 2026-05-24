import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Standalone output → small, self-contained runtime image for Docker.
  output: "standalone",
};

export default nextConfig;
