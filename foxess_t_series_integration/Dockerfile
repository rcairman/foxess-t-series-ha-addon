ARG BUILD_FROM=ghcr.io/hassio-addons/base:14.0.3
FROM ${BUILD_FROM}

# Install Python and paho-mqtt via Alpine packages
RUN apk add --no-cache python3 py3-paho-mqtt

# Copy files
COPY foxess_t_series_integration.py /usr/local/bin/foxess_t_series_integration.py
COPY rootfs /
RUN chmod +x /etc/services.d/foxess_t_series_integration/run