# Stage 1: Build the Go binary
FROM golang:1.23 AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Set proxy in case of network issues and download dependencies
RUN go env -w GOPROXY=https://proxy.golang.org,direct
RUN go mod download

# Copy the source code
COPY . .

# Set appropriate architecture and build the Go app
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o pastiepie

# Stage 2: Create the final image
FROM alpine:latest

# Install required CA certificates
RUN apk --no-cache add ca-certificates

# Set the Current Working Directory inside the container
WORKDIR /root

# Copy the binary from the builder stage to the final image
COPY --from=builder /app/pastiepie .

# Copy the necessary files for the application to run
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static

# Create the data directory for SQLite
RUN mkdir -p /root/data

# Ensure the binary has executable permissions
RUN chmod +x /root/pastiepie

# Expose port 8081 for HTTP traffic
EXPOSE 8081

# Command to run the Go application directly
CMD ["/root/pastiepie"]
