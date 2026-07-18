# syntax=docker/dockerfile:1
FROM rust:1-slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/icebox-macro/Cargo.toml crates/icebox-macro/Cargo.toml
RUN mkdir -p crates/icebox-macro/src \
    && echo "fn main() {}" > crates/icebox-macro/src/lib.rs \
    && cargo build --release \
    && rm -rf target/release/.fingerprint/icebox-* target/release/deps/icebox-*
COPY . .
RUN cargo build --release \
    && strip target/release/icebox-daemon \
    && cp target/release/icebox-daemon /usr/local/bin/icebox
FROM gcr.io/distroless/base-debian12:nonroot
COPY --from=build /usr/local/bin/icebox /usr/local/bin/icebox
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/icebox"]
CMD ["--api"]
