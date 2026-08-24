FROM golang:1.27.0-bookworm@sha256:484ef6066fa69acb059fdfeda7ba2b8f7391f2ef6abc6f9b8411e669ebd56466 AS build

ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.gitCommit=${GIT_COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o /bin/vespasian ./cmd/vespasian

FROM gcr.io/distroless/base-debian12@sha256:fabbf1c0c357a3d42550111351daed089b20a2c954df13ee2fcff60602515e84
COPY --from=build /bin/vespasian /usr/local/bin/vespasian
ENTRYPOINT ["vespasian"]
