FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/spool-relay ./cmd/spool-relay
COPY internal/relay ./internal/relay
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /relay ./cmd/spool-relay
RUN mkdir /data && chown 65532:65532 /data && chmod 700 /data

FROM scratch
COPY --from=build /relay /spool-relay
COPY --from=build --chown=65532:65532 /data /data
USER 65532:65532
ENV DATA_DIR=/data LISTEN_ADDR=:8443
EXPOSE 8443
ENTRYPOINT ["/spool-relay"]
