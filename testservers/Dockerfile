# Both test servers in one small image. mcpfuzz runs them with no network, a
# read-only root, no capabilities and an unprivileged user. Holds no secrets.
FROM golang:1.27-alpine@sha256:eb61c3873c97416fff0116553fff65d67a3549f72e11d9758849a689cdd8b523 AS build
WORKDIR /src
COPY go.mod ./
COPY testservers ./testservers
RUN CGO_ENABLED=0 go build -trimpath -o /out/ ./testservers/vulnerable ./testservers/fixed

# alpine, not scratch: the vulnerable server's shell-injection bug needs a shell.
FROM alpine:3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
COPY --from=build /out/vulnerable /out/fixed /usr/local/bin/
USER 65534:65534
