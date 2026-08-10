FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends krb5-kdc krb5-admin-server && \
    rm -rf /var/lib/apt/lists/*

COPY krb5.conf /etc/krb5.conf
COPY kdc.conf /etc/krb5kdc/kdc.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && mkdir -p /var/keytabs /var/lib/krb5kdc

EXPOSE 88/tcp 88/udp

ENTRYPOINT ["/entrypoint.sh"]
