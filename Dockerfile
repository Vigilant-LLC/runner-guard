FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X github.com/Vigilant-LLC/runner-guard/internal/cli.Version=${VERSION}" \
    -o /runner-guard ./cmd/runner-guard

FROM gcr.io/distroless/static-debian12
COPY --from=build /runner-guard /runner-guard
ENTRYPOINT ["/runner-guard"]
