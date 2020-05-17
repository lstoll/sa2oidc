FROM golang:1.14 AS build
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go install ./...

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /go/bin/sa2oidc /usr/bin/sa2oidc
ENTRYPOINT ["/usr/bin/sa2oidc"]
