# syntax=docker/dockerfile:1
# Snare: one CGO-free static binary on a distroless base.

FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG SNARE_VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags "-s -w -X main.version=${SNARE_VERSION}" -o /out/snare ./cmd/snare \
 && mkdir -p /out/var/lib/snare

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/snare /usr/local/bin/snare
# Owned by the nonroot user so a named volume mounted here is writable.
COPY --from=build --chown=65532:65532 /out/var/lib/snare /var/lib/snare
USER 65532:65532
WORKDIR /var/lib/snare
EXPOSE 8000 8780
ENTRYPOINT ["/usr/local/bin/snare"]
CMD ["serve", "-config", "/etc/snare/snare.yaml"]
