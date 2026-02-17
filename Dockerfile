FROM rust:1.93-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY static/ static/
COPY migrations/ migrations/
COPY .sqlx/ .sqlx/

ENV SQLX_OFFLINE=true
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends libsqlite3-0 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --no-create-home --shell /usr/sbin/nologin ironshare

COPY --from=builder /app/target/release/ironshare /usr/local/bin/ironshare

RUN mkdir -p /data && chown ironshare:ironshare /data

USER ironshare

ENV DATABASE_URL=sqlite:///data/ironshare.db?mode=rwc
ENV IRONSHARE_HOST=0.0.0.0
ENV IRONSHARE_PORT=3000

EXPOSE 3000

VOLUME ["/data"]

CMD ["ironshare"]
