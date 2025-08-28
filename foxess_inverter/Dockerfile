ARG BUILD_FROM=ghcr.io/hassio-addons/base:14.0.3
FROM ${BUILD_FROM}

# Install required packages
RUN apk add --no-cache python3 py3-pip

# Copy files
COPY run.sh /run.sh
COPY foxess_t_series_integration.py /foxess_t_series_integration.py

# Install paho-mqtt
RUN pip3 install paho-mqtt

# Permissions
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
