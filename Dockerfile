# ─── Stage 1: Builder ─────────────────────────────────────
FROM rust:1.85-slim AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN cargo build --release

# ─── Stage 2: Runtime ─────────────────────────────────────
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y ca-certificates libssl3 fonts-liberation && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/jecp /app/jecp

ENV JECP_HOST=0.0.0.0
ENV JECP_PORT=8080

EXPOSE 8080
CMD ["/app/jecp"]
