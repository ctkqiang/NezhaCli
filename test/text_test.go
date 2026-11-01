package test

import (
	"strings"
	"testing"

	"github.com/ctkqiang/nezha_cli/internal/text"
)

/*
TestTextWidth 验证 ASCII、CJK 与 ANSI 转义序列的显示宽度。
ANSI 颜色码不应计入终端列数，否则表格对齐会被破坏。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestTextWidth(t *testing.T) {
	cases := map[string]int{
		"":                   0,
		"abc":                3,
		"中文":                 4,
		"a中b":                4,
		"\033[31mred\033[0m": 3,
		"哪吒 Nezha":           10,
		"e\u0301":            1,
		"emoji 🚀":            8,
		"multi\nline":        10,
	}

	for value, want := range cases {
		if got := text.Width(value); got != want {
			t.Fatalf("Width(%q) = %d，期望 %d", value, got, want)
		}
	}
}

/*
TestTextPadRight 验证补齐到目标显示宽度，且不截断超宽内容。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestTextPadRight(t *testing.T) {
	if got := text.PadRight("abc", 5); got != "abc  " {
		t.Fatalf("ASCII 补齐错误: %q", got)
	}
	if got := text.PadRight("中文", 6); got != "中文  " {
		t.Fatalf("CJK 补齐错误: %q", got)
	}
	if got := text.PadRight("abcdef", 3); got != "abcdef" {
		t.Fatalf("超宽内容不应被截断: %q", got)
	}
}

/*
TestTextTruncate 验证按显示宽度截断并追加省略号，同时折叠换行。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestTextTruncate(t *testing.T) {
	if got := text.Truncate("abcdef", 4); got != "abc…" {
		t.Fatalf("ASCII 截断错误: %q", got)
	}
	if got := text.Truncate("中文测试", 5); got != "中文…" {
		t.Fatalf("CJK 截断错误: %q", got)
	}
	if got := text.Truncate("a\nb", 10); got != "a b" {
		t.Fatalf("换行应折叠为空格: %q", got)
	}
	if got := text.Truncate("abc", 0); got != "" {
		t.Fatalf("宽度 0 应返回空串: %q", got)
	}
}

/*
TestTextTable 验证表格每行显示宽度一致，中文不会错位。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestTextTable(t *testing.T) {
	table := text.Table(
		[]string{"名称", "说明"},
		[][]string{
			{"portscan", "并发端口扫描"},
			{"dns", "DNS 记录查询"},
		},
		24,
	)

	lines := strings.Split(strings.TrimRight(table, "\n"), "\n")
	if len(lines) != 6 {
		t.Fatalf("表格行数错误: %d\n%s", len(lines), table)
	}

	width := text.Width(lines[0])
	for index, line := range lines {
		if got := text.Width(line); got != width {
			t.Fatalf("第 %d 行宽度 %d 与边框 %d 不一致: %q", index, got, width, line)
		}
	}
	if !strings.Contains(table, "portscan") || !strings.Contains(table, "DNS 记录查询") {
		t.Fatalf("表格缺少内容:\n%s", table)
	}
}

/*
TestTextSection 验证段落标题格式。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestTextSection(t *testing.T) {
	if got := text.Section("模块"); got != "\n▌ 模块\n" {
		t.Fatalf("段落标题格式错误: %q", got)
	}
}

/*
TestTextKeyValues 验证键值表包含全部字段。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestTextKeyValues(t *testing.T) {
	table := text.KeyValues([][2]string{
		{"主机", "10.0.0.1"},
		{"端口", "443"},
	}, 32)
	if !strings.Contains(table, "10.0.0.1") || !strings.Contains(table, "443") {
		t.Fatalf("键值表缺少内容:\n%s", table)
	}
}
