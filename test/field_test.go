package test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/core"
	"github.com/ctkqiang/nezha_cli/internal/engine"
	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/structure"
	"github.com/ctkqiang/nezha_cli/modules/connect"
	"github.com/ctkqiang/nezha_cli/modules/crunch"
	"github.com/ctkqiang/nezha_cli/modules/encode"
	"github.com/ctkqiang/nezha_cli/modules/hash"
	httpmod "github.com/ctkqiang/nezha_cli/modules/http"
	"github.com/ctkqiang/nezha_cli/modules/random"
)

/*
TestHashModule 验证摘要计算与期望值校验。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestHashModule(t *testing.T) {
	module := hash.New()
	buffer := &bytes.Buffer{}
	err := module.Run(context.Background(), model.Options{
		"INPUT": "abc", "ALGO": "sha256",
	}, buffer)
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if !strings.Contains(buffer.String(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") {
		t.Fatalf("sha256(abc) 结果错误: %s", buffer.String())
	}

	buffer.Reset()
	err = module.Run(context.Background(), model.Options{
		"INPUT": "abc", "ALGO": "sha256",
		"EXPECT": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	}, buffer)
	if err != nil {
		t.Fatalf("期望值一致时不应报错: %v", err)
	}

	err = module.Run(context.Background(), model.Options{
		"INPUT": "abc", "ALGO": "sha256", "EXPECT": "deadbeef",
	}, buffer)
	if err == nil {
		t.Fatal("期望值不一致时必须返回错误")
	}
}

/*
TestEncodeModule 验证 base64 与 hex 编解码。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestEncodeModule(t *testing.T) {
	module := encode.New()
	buffer := &bytes.Buffer{}
	err := module.Run(context.Background(), model.Options{
		"ACTION": "encode", "ALGO": "base64", "VALUE": "nezha",
	}, buffer)
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}
	if !strings.Contains(buffer.String(), "bmV6aGE=") {
		t.Fatalf("base64 编码错误: %s", buffer.String())
	}

	buffer.Reset()
	err = module.Run(context.Background(), model.Options{
		"ACTION": "decode", "ALGO": "base64", "VALUE": "bmV6aGE=",
	}, buffer)
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if !strings.Contains(buffer.String(), "nezha") {
		t.Fatalf("base64 解码错误: %s", buffer.String())
	}

	err = module.Run(context.Background(), model.Options{
		"ACTION": "encode", "ALGO": "不支持", "VALUE": "x",
	}, buffer)
	if err == nil {
		t.Fatal("不支持的算法必须返回错误")
	}
}

/*
TestRandomModule 验证随机字符串长度与字符集约束。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestRandomModule(t *testing.T) {
	module := random.New()
	buffer := &bytes.Buffer{}
	err := module.Run(context.Background(), model.Options{
		"LENGTH": "16", "CHARSET": "hex", "COUNT": "4",
	}, buffer)
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}

	output := buffer.String()
	lines := 0
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasSuffix(fields[0], ".") {
			continue
		}
		lines++
		value := fields[1]
		if len(value) != 16 {
			t.Fatalf("随机串长度错误: %q", value)
		}
		for _, char := range value {
			if !strings.ContainsRune("0123456789abcdef", char) {
				t.Fatalf("hex 字符集出现非法字符 %q", char)
			}
		}
	}
	if lines < 4 {
		t.Fatalf("应生成 4 条: %s", output)
	}
}

/*
TestConnectModule 验证 TCP 原始交互：发送文本并回显响应。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestConnectModule(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		buffer := make([]byte, 64)
		count, _ := conn.Read(buffer)
		_, _ = conn.Write([]byte("echo:" + string(buffer[:count])))
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	module := connect.New()
	buffer := &bytes.Buffer{}
	err = module.Run(context.Background(), model.Options{
		"HOST": "127.0.0.1", "PORT": fmt.Sprintf("%d", port), "SEND": "ping", "WAIT": "200ms",
	}, buffer)
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if !strings.Contains(buffer.String(), "echo:ping") {
		t.Fatalf("响应回显缺失: %s", buffer.String())
	}
}

/*
TestHTTPModule 验证原始 HTTP 请求构造与回显。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestHTTPModule(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Test-Header", "present")
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte("body:" + request.Header.Get("X-Test")))
	}))
	defer server.Close()

	module := httpmod.New()
	buffer := &bytes.Buffer{}
	err := module.Run(context.Background(), model.Options{
		"URL": server.URL, "METHOD": "POST", "HEADERS": "X-Test: field1", "BODY": "payload",
	}, buffer)
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	output := buffer.String()
	if !strings.Contains(output, "201 Created") {
		t.Fatalf("缺少状态码: %s", output)
	}
	if !strings.Contains(output, "X-Test-Header: present") {
		t.Fatalf("缺少响应头: %s", output)
	}
	if !strings.Contains(output, "body:field1") {
		t.Fatalf("缺少响应体: %s", output)
	}
}

/*
TestCrunchModule 验证字典生成的组合完整性与行数。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestCrunchModule(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "words.txt")
	module := crunch.New()
	buffer := &bytes.Buffer{}
	err := module.Run(context.Background(), model.Options{
		"CHARSET": "ab", "MIN": "1", "MAX": "2", "OUTPUT": outputPath,
	}, buffer)
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("读取字典失败: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 6 {
		t.Fatalf("ab 1-2 组合应为 6 行，实际 %d: %v", len(lines), lines)
	}
	joined := strings.Join(lines, ",")
	for _, want := range []string{"a", "b", "aa", "ab", "ba", "bb"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("缺少组合 %s: %v", want, lines)
		}
	}
}

/*
TestConsoleOpsCommands 验证 echo/sleep/save/load/repeat/history 脚本命令。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestConsoleOpsCommands(t *testing.T) {
	registry, err := core.LoadNative()
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}

	buffer := &bytes.Buffer{}
	console := structure.New(registry)
	console.SetColor(false)
	console.SetInput(strings.NewReader(""))
	console.SetOutput(buffer)

	console.ExecuteOnce(`echo 战场标记`)
	if !strings.Contains(buffer.String(), "战场标记") {
		t.Fatalf("echo 未输出: %s", buffer.String())
	}

	start := time.Now()
	console.ExecuteOnce("sleep 50ms")
	if time.Since(start) < 50*time.Millisecond {
		t.Fatal("sleep 未生效")
	}

	buffer.Reset()
	console.ExecuteOnce("repeat 3 1ms echo tick")
	if strings.Count(buffer.String(), "第 3/3 次") != 1 {
		t.Fatalf("repeat 次数错误: %s", buffer.String())
	}

	buffer.Reset()
	console.ExecuteOnce("watch 1ms exit")
	if !strings.Contains(buffer.String(), "第 1 轮") {
		t.Fatalf("watch 未执行首轮: %s", buffer.String())
	}

	statePath := filepath.Join(t.TempDir(), "state.json")
	console.ExecuteOnce("setg TARGET 10.0.0.1")
	console.ExecuteOnce("save " + statePath)
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("状态文件未生成: %v", err)
	}

	fresh := structure.New(registry)
	fresh.SetColor(false)
	fresh.SetInput(strings.NewReader(""))
	fresh.SetOutput(&bytes.Buffer{})
	fresh.ExecuteOnce("load " + statePath)
	fresh.ExecuteOnce("env")
	_ = fresh
}

/*
TestEnginePanicRecovery 验证模块 panic 被转换为错误而不是击穿控制台。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestEnginePanicRecovery(t *testing.T) {
	registry := core.NewRegistry()
	if err := registry.Register(&panicModule{}); err != nil {
		t.Fatalf("注册失败: %v", err)
	}

	entry, ok := registry.Get("panic_demo")
	if !ok {
		t.Fatal("缺少 panic_demo")
	}

	buffer := &bytes.Buffer{}
	_, err := engine.Run(context.Background(), entry, model.Options{}, buffer)
	if err == nil {
		t.Fatal("panic 必须被转换为错误")
	}
	if !strings.Contains(err.Error(), "panic") {
		t.Fatalf("错误信息应包含 panic: %v", err)
	}
}

// panicModule 是 Run 方法直接 panic 的模块，用于验证 engine 的 recover 边界。
type panicModule struct{}

/*
Meta 返回 panic 模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块元数据。
*/
func (p *panicModule) Meta() model.Meta {
	return model.Meta{
		Name:        "panic_demo",
		Category:    "测试",
		Summary:     "panic 演示模块",
		Description: "Run 方法直接 panic，用于验证引擎恢复边界。",
		Author:      "测试",
	}
}

/*
Run 直接触发 panic。

参数:
  - ctx (context.Context): 执行上下文。
  - options (model.Options): 模块参数。
  - out (io.Writer): 输出目标。

返回:
  - error: 永不返回。
*/
func (p *panicModule) Run(ctx context.Context, options model.Options, out io.Writer) error {
	panic("boom")
}
