# Use the official Golang image to build our application
FROM golang:1.22-alpine AS builder

# Set working directory
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are unchanged
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the application
# CGO_ENABLED=0 is important for creating a static binary
# -a ensures all packages are rebuilt (useful for alpine image)
# -installsuffix cgo ensures different naming for cgo-dependent binaries
RUN CGO_ENABLED=0 GOOS=linux go build -o /goshrinkit ./cmd/api

# Start a new stage to create a smaller final image
FROM alpine:latest

# Install ca-certificates to ensure HTTPS works
RUN apk --no-cache add ca-certificates

# Set working directory
WORKDIR /root/

# Copy the compiled application from the builder stage
COPY --from=builder /goshrinkit .

# Copy the web frontend files
COPY --from=builder /app/web ./web

# Expose the port the app runs on
EXPOSE 8080

# Run the application
CMD ["./goshrinkit"]
