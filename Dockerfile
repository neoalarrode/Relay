ARG BUILD_FROM
FROM ${BUILD_FROM}

RUN apk add --no-cache python3

COPY relay.py /
COPY run.sh /
RUN chmod +x /run.sh

CMD ["/run.sh"]
