# Use the official Golang image to build our application
FROM golang:1.22-alpine AS builder

# Set working directory
WORKDIR /app

# Install git and ca-certificates in the builder stage
# This ensures that 'go mod download' can fetch modules via HTTPS and git if needed.
RUN apk add --no-cache git ca-certificates

# Copy go mod and sum files
COPY go.mod go.sum ./

# Ensure Go modules are clean and explicitly set a robust GOPROXY
# This can help with network issues and ensure dependencies are resolved correctly.
ENV GOPROXY=https://proxy.golang.org,direct
RUN go mod tidy
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the application
# CGO_ENABLED=0 is important for creating a static binary
# We now build the main.go directly from the root of the app directory (where it will be moved)
RUN CGO_ENABLED=0 GOOS=linux go build -o /goshrink.it .

# Start a new stage to create a smaller final image
FROM alpine:latest

# Install ca-certificates to ensure HTTPS works in the final image as well
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
