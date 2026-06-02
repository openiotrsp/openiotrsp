FROM golang:1.26-alpine AS build

WORKDIR /src
RUN apk add --no-cache ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG APP
RUN CGO_ENABLED=0 go build -o /out/openiotrsp ./cmd/${APP}

FROM alpine:3.22

RUN apk add --no-cache ca-certificates
WORKDIR /app

COPY --from=build /out/openiotrsp /app/openiotrsp
COPY migrations /app/migrations
COPY spec /app/spec

ENTRYPOINT ["/app/openiotrsp"]
