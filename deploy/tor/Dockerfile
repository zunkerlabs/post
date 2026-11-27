# tor publishing the Mailbox Server's onion service. See deploy/README.md.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends tor \
 && rm -rf /var/lib/apt/lists/* \
 && install -d -o debian-tor -g debian-tor -m 700 /var/lib/tor /var/lib/tor/zunker
COPY torrc /etc/tor/torrc
USER debian-tor
CMD ["tor", "-f", "/etc/tor/torrc"]
