# Build a static Go binary (pure-Go pgx driver → CGO disabled) and ship on distroless.
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY server/go.mod server/go.sum ./
RUN go mod download
COPY server/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/sentinel-server ./cmd/server

FROM gcr.io/distroless/base-debian12:nonroot
WORKDIR /app
COPY --from=build /out/sentinel-server /app/sentinel-server
COPY server/rules /app/rules
ENV SENTINEL_RULES_DIR=/app/rules
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/sentinel-server"]
