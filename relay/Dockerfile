ARG BUILD_FROM
FROM ${BUILD_FROM}

RUN apk add --no-cache python3

COPY relay.py /

ENTRYPOINT []
CMD ["python3", "/relay.py", "--ha-addon"]
