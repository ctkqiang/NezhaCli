package test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ctkqiang/nezha_cli/internal/core"
	"github.com/ctkqiang/nezha_cli/internal/structure"
	"github.com/ctkqiang/nezha_cli/internal/text"
)

/*
TestTextTermWidth 验证终端宽度读取与环境变量回退。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestTextTermWidth(t *testing.T) {
	t.Setenv("COLUMNS", "120")
	if got := text.TermWidth(); got != 120 {
		t.Fatalf("COLUMNS=120 应返回 120，实际 %d", got)
	}

	t.Setenv("COLUMNS", "10")
	if got := text.TermWidth(); got < 40 {
		t.Fatalf("过窄宽度应被提升到下限 40，实际 %d", got)
	}

	t.Setenv("COLUMNS", "非法")
	if got := text.TermWidth(); got != 80 {
		t.Fatalf("非法 COLUMNS 应回退 80，实际 %d", got)
	}
}

/*
TestTextTruncateANSI 验证 ANSI 转义序列不因截断而断裂。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestTextTruncateANSI(t *testing.T) {
	// 复位码位于截断点之前时应原样保留；截断点之后的转义序列自然丢弃
	colored := "\033[31m红\033[0m" + "很长很长很长很长"
	truncated := text.Truncate(colored, 6)
	if !strings.Contains(truncated, "\033[31m") || !strings.Contains(truncated, "\033[0m") {
		t.Fatalf("截断不应破坏截断点前的颜色码: %q", truncated)
	}
	if text.Width(truncated) > 6 {
		t.Fatalf("截断后显示宽度超限: %d > 6", text.Width(truncated))
	}
}

/*
TestTextTableStyled 验证样式着色与纯文本两种输出。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestTextTableStyled(t *testing.T) {
	headers := []string{"参数", "值"}
	rows := [][]string{{"目标", "10.0.0.1"}}

	styled := text.TableStyled(headers, rows, 20, text.TableStyle{
		Border: "\033[90m", Header: "\033[1;36m", Reset: "\033[0m",
	})
	if !strings.Contains(styled, "\033[90m") || !strings.Contains(styled, "\033[1;36m") {
		t.Fatalf("样式表格应包含颜色码: %q", styled)
	}

	plain := text.Table(headers, rows, 20)
	if strings.Contains(plain, "\033[") {
		t.Fatalf("纯文本表格不应包含颜色码: %q", plain)
	}
}

/*
TestConsoleBannerCapacity 验证启动横幅列出内置能力清单。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestConsoleBannerCapacity(t *testing.T) {
	registry, err := core.LoadNative()
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}

	buffer := &bytes.Buffer{}
	console := structure.New(registry)
	console.SetColor(false)
	console.SetInput(strings.NewReader("exit\n"))
	console.SetOutput(buffer)

	if err := console.Start(); err != nil {
		t.Fatalf("启动失败: %v", err)
	}

	output := buffer.String()
	for _, want := range []string{
		"哪 吒 网 络 安 全 终 端",
		"哪吒网络安全终端",
		"内置 31 个模块",
		"侦察",
		"三步上手",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("横幅缺少 %q:\n%s", want, output)
		}
	}
}

/*
TestConsoleShowCategoriesBars 验证类别分布条形图渲染。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestConsoleShowCategoriesBars(t *testing.T) {
	registry, err := core.LoadNative()
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}

	buffer := &bytes.Buffer{}
	console := structure.New(registry)
	console.SetColor(false)
	console.SetOutput(buffer)

	console.ExecuteOnce("show categories")
	output := buffer.String()
	if !strings.Contains(output, "▓") || !strings.Contains(output, "能力分布") {
		t.Fatalf("类别条形图缺失: %s", output)
	}
}

/*
TestConsoleShowModulesGrouped 验证模块列表按类别分组渲染。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestConsoleShowModulesGrouped(t *testing.T) {
	registry, err := core.LoadNative()
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}

	buffer := &bytes.Buffer{}
	console := structure.New(registry)
	console.SetColor(false)
	console.SetOutput(buffer)

	console.ExecuteOnce("show modules")
	output := buffer.String()
	for _, want := range []string{"侦察 · 9 个模块", "Web · 9 个模块", "无线 · 6 个模块", "系统 · 6 个模块"} {
		if !strings.Contains(output, want) {
			t.Fatalf("分组标题缺少 %q:\n%s", want, output)
		}
	}
}
