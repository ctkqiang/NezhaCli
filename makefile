.PHONY: build build-local run test clean format

APP_NAME = nezha
BINARY_PATH = bin/
TARGET = $(BINARY_PATH)$(APP_NAME)
LDFLAGS = -s -w -extldflags '-static'

build:
	@echo "[+] 开始 Termux/ARM64 静态编译 $(APP_NAME)..."
	@mkdir -p $(BINARY_PATH)
	@GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(TARGET) ./cmd/nezha
	@chmod +x $(TARGET)
	@echo "[★] 编译完成: $(TARGET)"

build-local:
	@echo "[+] 开始本机编译 $(APP_NAME)..."
	@mkdir -p $(BINARY_PATH)
	@go build -trimpath -o $(BINARY_PATH)$(APP_NAME)-local ./cmd/nezha
	@chmod +x $(BINARY_PATH)$(APP_NAME)-local
	@echo "[★] 本机编译完成: $(BINARY_PATH)$(APP_NAME)-local"

run:
	@go run ./cmd/nezha

test:
	@go test ./...

clean:
	@echo "[-] 清除 $(BINARY_PATH) 目录 ..."
	@rm -rf $(BINARY_PATH)

format:
	@echo "[+] 执行 go fmt 整理代码 ..."
	@go fmt ./...
