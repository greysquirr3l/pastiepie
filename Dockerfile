# Stage 1: Build the Go binary
FROM golang:1.23 AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Set Go proxy and download dependencies
RUN go env -w GOPROXY=https://proxy.golang.org,direct
RUN go mod download

# Copy the source code
COPY . .

# Build the Go binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o pastiepie

# Stage 2: Create the final image
FROM alpine:latest

# Install required packages: Nginx, Supervisor, and certificates
RUN apk --no-cache add ca-certificates nginx supervisor bash

# Set the working directory for the application
WORKDIR /root

# Copy the binary from the builder stage
COPY --from=builder /app/pastiepie .

# Copy application files (templates, static files, etc.)
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static

# Copy configuration files
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY supervisord.conf /etc/supervisord.conf

# Copy the helper script to set up environment variables
COPY setup_env.sh /root/setup_env.sh
RUN chmod +x /root/setup_env.sh

# Create the data directory for the database
RUN mkdir -p /root/data

# Expose the application port
EXPOSE 8081

# Run the helper script and Supervisor
CMD ["/bin/bash", "-c", "/root/setup_env.sh && /usr/bin/supervisord -c /etc/supervisord.conf"]
