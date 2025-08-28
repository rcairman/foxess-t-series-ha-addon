ARG BUILD_FROM=ghcr.io/hassio-addons/base:14.0.3
FROM ${BUILD_FROM}

# Install Python and paho-mqtt via Alpine packages
RUN apk add --no-cache python3 py3-paho-mqtt

# Copy files
COPY run.sh /run.sh
COPY foxess_t_series_integration.py /foxess_t_series_integration.py

# Permissions
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]