# Reference image for API conformance: the unmodified Go server from this
# checkout, built with a stub frontend. Only the API surface is under test, so
# the web bundle is not built. Build context is the repository root.
#
# One stage on purpose: BuildKit runs stages in parallel, and a Go build next to
# an apt install exhausts a small Docker VM. The Go build is also limited to two
# packages at once for the same reason.
FROM golang:1.26
ENV CGO_ENABLED=1
ENV GOPROXY=https://proxy.golang.org,direct
ENV GOPRIVATE=github.com/Silo-Server/*
ENV GONOSUMDB=github.com/Silo-Server/*
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl ffmpeg libvips-dev fontconfig fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY go.mod go.sum ./
COPY internal/compat/zishang520-webtransport-go/ internal/compat/zishang520-webtransport-go/
RUN --mount=type=cache,target=/go/pkg/mod,id=silo-conformance-gomod,sharing=locked \
    go mod download
COPY internal/ internal/
COPY migrations/ migrations/
COPY contracts/ contracts/
COPY cmd/ cmd/
COPY web/embed.go web/embed.go
RUN mkdir -p web/dist && printf '<!doctype html>\n' > web/dist/index.html
ARG BUILD_REVISION=unknown
ARG BUILD_DIRTY=false
RUN --mount=type=cache,target=/root/.cache/go-build,id=silo-conformance-gobuild \
    --mount=type=cache,target=/go/pkg/mod,id=silo-conformance-gomod,sharing=locked \
    GOMEMLIMIT=3500MiB go build -p 2 \
      -ldflags "-X github.com/Silo-Server/silo-server/internal/buildinfo.revisionOverride=${BUILD_REVISION} -X github.com/Silo-Server/silo-server/internal/buildinfo.dirtyOverride=${BUILD_DIRTY}" \
      -o /usr/local/bin/silo ./cmd/silo/
RUN mkdir -p /var/lib/silo /tmp/silo-transcode /tmp/silo-download-artifacts
WORKDIR /var/lib/silo
ENTRYPOINT ["silo"]
