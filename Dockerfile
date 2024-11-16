# Start from the official Golang image for building the binary
FROM golang:1.19 as builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the Go app
RUN go build -o pastiepie

# Start a new stage from scratch for the final image
FROM alpine:latest

# Install certificates and necessary packages
RUN apk --no-cache add ca-certificates

# Set the Current Working Directory inside the container
WORKDIR /root/

# Copy the binary and other necessary files from the builder stage
COPY --from=builder /app/pastiepie .
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static

# Expose port 8080 for HTTP traffic
EXPOSE 8080

# Command to run the executable
CMD ["./pastiepie"]
