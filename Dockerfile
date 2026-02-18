FROM golang:1.24 AS build

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /bin/vespasian ./cmd/vespasian

FROM gcr.io/distroless/static-debian12
COPY --from=build /bin/vespasian /usr/local/bin/vespasian
ENTRYPOINT ["vespasian"]
