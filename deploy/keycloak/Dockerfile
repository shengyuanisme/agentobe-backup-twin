FROM quay.io/keycloak/keycloak:26.7.0 AS builder

ENV KC_DB=postgres \
    KC_HEALTH_ENABLED=true \
    KC_METRICS_ENABLED=true

WORKDIR /opt/keycloak
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:26.7.0

COPY --from=builder /opt/keycloak/ /opt/keycloak/
COPY deploy/keycloak/realm-agentobe.json /opt/keycloak/data/import/realm-agentobe.json

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized", "--import-realm"]
