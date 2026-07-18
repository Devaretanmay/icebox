# syntax=docker/dockerfile:1
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --bin icebox-daemon \
    && strip target/release/icebox-daemon \
    && cp target/release/icebox-daemon /usr/local/bin/icebox
FROM gcr.io/distroless/base-debian12:nonroot
COPY --from=build /usr/local/bin/icebox /usr/local/bin/icebox
COPY --from=build /usr/lib/aarch64-linux-gnu/libgcc_s.so.1 /usr/lib/aarch64-linux-gnu/libgcc_s.so.1
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/icebox"]
CMD ["--api"]
