FROM golang:1.24 AS build

ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.gitCommit=${GIT_COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o /bin/vespasian ./cmd/vespasian

FROM gcr.io/distroless/static-debian12
COPY --from=build /bin/vespasian /usr/local/bin/vespasian
ENTRYPOINT ["vespasian"]
