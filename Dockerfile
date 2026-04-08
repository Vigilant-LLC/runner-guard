FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X github.com/Vigilant-LLC/runner-guard/internal/cli.Version=${VERSION}" \
    -o /runner-guard ./cmd/runner-guard

FROM gcr.io/distroless/static-debian12
LABEL org.opencontainers.image.source="https://github.com/Vigilant-LLC/runner-guard"
LABEL org.opencontainers.image.description="CI/CD supply chain security scanner for GitHub Actions"
LABEL org.opencontainers.image.license="AGPL-3.0"
COPY --from=build /runner-guard /runner-guard
ENTRYPOINT ["/runner-guard"]
