# Stage 1: Build the Go binary
FROM golang:1.23 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o pastiepie

# Stage 2: Final container
FROM alpine:latest

RUN apk --no-cache add ca-certificates bash supervisor nginx

WORKDIR /root
COPY --from=builder /app/pastiepie .
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static
COPY supervisord.conf /etc/supervisord.conf
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY setup_env.sh /root/setup_env.sh

RUN chmod +x /root/setup_env.sh

CMD ["/bin/bash", "-c", "/root/setup_env.sh && /usr/bin/supervisord -c /etc/supervisord.conf"]

EXPOSE 80
