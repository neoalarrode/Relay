ARG BUILD_FROM
FROM ${BUILD_FROM}

RUN apk add --no-cache python3

COPY relay.py /usr/local/bin/
COPY run.sh /etc/services.d/relay/run
RUN chmod +x /etc/services.d/relay/run
