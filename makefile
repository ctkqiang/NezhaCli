
.PHONY: build build-local run clean format

APP_NAME = nezha
BINARY_PATH = bin/
TARGET = $(BINARY_PATH)$(APP_NAME)

build:
	@echo "[+] 开始跨平台编译 $(APP_NAME)..."
	@mkdir -p $(BINARY_PATH)
	@rm -f $(TARGET)
	go build -a -o $(TARGET) ./cmd/nezha/main.go
	@chmod +x $(TARGET)
	@echo "[★] 编译完成: $(TARGET)"

run: build
	@echo "[+] 正在启动测试引擎 ..."
	./$(TARGET)

clean:
	@echo "[-] 清除 $(BINARY_PATH) 目录 ..."
	@rm -rf $(BINARY_PATH)

format:
	@echo "[+] 执行 go fmt 整理代码 ..."
	@go fmt ./...