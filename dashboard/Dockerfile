# Sentinel Next.js console — production image (standalone output).
FROM node:22-bookworm-slim AS build
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
# Cap Node's heap — on high-RAM hosts Node otherwise sizes a huge heap and the build
# process gets OOM-killed at startup. 4 GB is ample for this app.
ENV NODE_OPTIONS=--max-old-space-size=4096
RUN pnpm build

FROM node:22-bookworm-slim AS run
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
# better-auth CLI needs the deps + config at migrate time; copy the standalone runtime
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
COPY --from=build /app/public ./public
EXPOSE 3000
CMD ["node", "server.js"]
