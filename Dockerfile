FROM golang:1.22-alpine AS builder

WORKDIR /src

COPY go.mod ./
RUN go mod download && go mod tidy

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w -extldflags=-static" \
    -o /app/server ./main.go

FROM scratch

COPY --from=builder /app/server /server

USER 65534:65534

EXPOSE 8080

ENTRYPOINT ["/server"]
