cd ../backend
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o go-server main.go
podman cp go-server go-backend:/app/go-server
podman exec go-backend chmod +x /app/go-server
podman restart go-backend
