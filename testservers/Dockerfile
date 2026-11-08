# Both test servers in one small image. mcpfuzz runs them with no network, a
# read-only root, no capabilities and an unprivileged user. Holds no secrets.
FROM golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
WORKDIR /src
COPY go.mod ./
COPY testservers ./testservers
RUN CGO_ENABLED=0 go build -trimpath -o /out/ ./testservers/vulnerable ./testservers/fixed

# alpine, not scratch: the vulnerable server's shell-injection bug needs a shell.
FROM alpine:3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
COPY --from=build /out/vulnerable /out/fixed /usr/local/bin/
USER 65534:65534
