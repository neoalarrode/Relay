#!/usr/bin/with-contenv bashio

PORT=$(bashio::config 'port')
IFACE=$(bashio::config 'mcast_interface')
MAX=$(bashio::config 'max_clients')
BUF=$(bashio::config 'buffer_kb')

bashio::log.info "Movistar IPTV Relay v1.0.0"
bashio::log.info "  Puerto: ${PORT}"
bashio::log.info "  Interfaz multicast: ${IFACE}"
bashio::log.info "  Max clientes: ${MAX}"
bashio::log.info "  Buffer: ${BUF} KB"

exec python3 /usr/local/bin/relay.py \
    --port "${PORT}" \
    --interface "${IFACE}" \
    --max-clients "${MAX}" \
    --buffer "${BUF}"
