# Stage 1: Build the Go binary
FROM golang:1.20 AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Set proxy in case of network issues and download dependencies
RUN go env -w GOPROXY=https://proxy.golang.org,direct
RUN go mod download

# Copy the source code
COPY . .

# Build the Go app (statically linked for Alpine)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o pastiepie

# Stage 2: Create the final image
FROM alpine:latest

# Install Nginx, Supervisor, and certificates
RUN apk --no-cache add ca-certificates nginx supervisor

# Set the Current Working Directory inside the container
WORKDIR /root

# Copy the binary from the builder stage to the final image
COPY --from=builder /app/pastiepie .

# Copy the necessary files for the application to run
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static

# Copy Nginx configuration
COPY nginx/nginx.conf /etc/nginx/nginx.conf

# Copy Supervisor configuration
COPY supervisord.conf /etc/supervisord.conf

# Add default config.yml for the application
COPY config.yml /root/config.yml

# Create the data directory for SQLite
RUN mkdir -p /root/data

# Ensure the binary has executable permissions
RUN chmod +x /root/pastiepie

# Expose port 80 for HTTP traffic (Nginx)
EXPOSE 80

# Command to run supervisord, which will manage Nginx and the Go application
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
