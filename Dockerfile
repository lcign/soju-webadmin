FROM golang:1.23-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /soju-webadmin .

FROM scratch
# TLS to soju needs the trust store; a self-signed setup uses -soju-insecure instead.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /soju-webadmin /soju-webadmin
EXPOSE 8080
ENTRYPOINT ["/soju-webadmin"]
CMD ["-listen", "0.0.0.0:8080"]
