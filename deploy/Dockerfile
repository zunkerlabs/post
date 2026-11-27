# zunker-cli, which runs the Mailbox Server with `serve`. See deploy/README.md.
FROM rust:1.92-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p zunker-cli

FROM debian:bookworm-slim
RUN useradd --system --home-dir /var/lib/zunker --shell /usr/sbin/nologin zunker \
 && install -d -o zunker -g zunker -m 700 /var/lib/zunker
COPY --from=build /src/target/release/zunker-cli /usr/local/bin/zunker-cli
USER zunker
ENTRYPOINT ["zunker-cli"]
