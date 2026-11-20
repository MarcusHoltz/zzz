# Tests and linters run in CI (.github/workflows/ci.yml); this only builds.
# The base image is pinned by digest; Dependabot updates it.
FROM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /message-me-cve ./cmd/message-me-cve

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /message-me-cve /message-me-cve
USER 1000:1000
WORKDIR /data
ENTRYPOINT ["/message-me-cve"]
