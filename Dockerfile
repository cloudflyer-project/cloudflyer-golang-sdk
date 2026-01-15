# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the CLI binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /cfsolver ./cmd/cfsolver

# Runtime stage
FROM alpine:3.21

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN adduser -D -u 1000 cfsolver

# Copy binary from builder
COPY --from=builder /cfsolver /usr/local/bin/cfsolver

# Switch to non-root user
USER cfsolver

ENTRYPOINT ["cfsolver"]
CMD ["--help"]
