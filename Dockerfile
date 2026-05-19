FROM rust:1.75-slim AS builder

WORKDIR /app
COPY . .

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/aegis /usr/local/bin/aegis
COPY --from=builder /app/configs/default.toml /etc/aegis/config.toml

ENV AEGIS_CONFIG=/etc/aegis/config.toml

ENTRYPOINT ["aegis"]
CMD ["--help"]
