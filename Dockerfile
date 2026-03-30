FROM scratch

COPY --from=alpine:latest /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/skpr-tetragon-exec-sidecar /usr/local/bin/skpr-tetragon-exec-sidecar

CMD ["skpr-tetragon-exec-sidecar"]
