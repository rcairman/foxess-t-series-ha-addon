ARG BUILD_FROM=ghcr.io/hassio-addons/base:14.0.3
FROM ${BUILD_FROM}

COPY rootfs /

# Upewniamy się, że plik run ma +x
RUN chmod +x /etc/services.d/hello/run