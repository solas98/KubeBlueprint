.PHONY: run build tidy docker clean

BINARY=k8s-blueprint
PORT?=8080

## Run development server
run:
	go run ./main.go --port $(PORT)

## Build binary
build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o ./bin/$(BINARY) ./main.go

## Tidy Go modules
tidy:
	go mod tidy

## Build Docker image
docker:
	docker build -t $(BINARY):latest .

## Run Docker container
docker-run:
	docker run --rm -p $(PORT):8080 $(BINARY):latest

## Clean build artifacts
clean:
	rm -rf ./bin

## Download Go dependencies
deps:
	go mod download
