FROM rust:1.97.1-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        libclang-dev \
        libxml2-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY apps/axum-product/ ./
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libxml2 && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 benchmark
COPY --from=build /src/target/release/rig-benchmark-rust-axum /usr/local/bin/benchmark
USER benchmark
WORKDIR /home/benchmark
ENV BENCHMARK_BIND=0.0.0.0:3000
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/benchmark"]
