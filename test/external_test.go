package test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ctkqiang/nezha_cli/internal/core"
	"github.com/ctkqiang/nezha_cli/internal/model"
)

/*
writeStubModule 写入一个 SanTaiZi SDK 兼容的 shell 模块桩。
桩程序实现 --info 与 --execute 两种调用，用于验证适配器协议。

参数:
  - t (*testing.T): 测试上下文。
  - directory (string): 目标目录。
  - name (string): 文件名。

返回:
  - string: 模块绝对路径。
*/
func writeStubModule(t *testing.T, directory string, name string) string {
	t.Helper()

	script := `#!/bin/sh
if [ "$1" = "--info" ]; then
  echo "name:stub_module"
  echo "description:外部模块桩"
  echo "cnvd:CNVD-2024-0001"
  echo "cve:CVE-2024-0001"
  echo "option:TARGET:string:true:"
  echo "option:MODE:string:false:fast"
  exit 0
fi
if [ "$1" = "--execute" ]; then
  shift
  echo "stub-exec $@"
  exit 0
fi
echo "unknown mode" >&2
exit 2
`

	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("写入模块桩失败: %v", err)
	}
	return path
}

/*
TestExternalModuleInfo 验证 --info 元数据解析与选项归一化。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestExternalModuleInfo(t *testing.T) {
	directory := t.TempDir()
	path := writeStubModule(t, directory, "stub")

	module, err := core.NewExternalModule(path)
	if err != nil {
		t.Fatalf("加载外部模块失败: %v", err)
	}

	meta := module.Meta()
	if meta.Name != "stub_module" {
		t.Fatalf("模块名错误: %s", meta.Name)
	}
	if meta.Category != "外部" {
		t.Fatalf("类别错误: %s", meta.Category)
	}
	if meta.Summary != "外部模块桩" {
		t.Fatalf("摘要错误: %s", meta.Summary)
	}
	if len(meta.Options) != 2 {
		t.Fatalf("选项数量错误: %d", len(meta.Options))
	}
	if meta.Options[0].Name != "TARGET" || !meta.Options[0].Required {
		t.Fatalf("必填选项解析错误: %+v", meta.Options[0])
	}
	if meta.Options[0].Description != "类型: string" {
		t.Fatalf("选项类型标注错误: %+v", meta.Options[0])
	}
	if meta.Options[1].Name != "MODE" || meta.Options[1].Default != "fast" {
		t.Fatalf("默认值解析错误: %+v", meta.Options[1])
	}

	references := strings.Join(meta.References, ",")
	if !strings.Contains(references, "CNVD: CNVD-2024-0001") {
		t.Fatalf("CNVD 引用缺失: %v", meta.References)
	}
	if !strings.Contains(references, "CVE: CVE-2024-0001") {
		t.Fatalf("CVE 引用缺失: %v", meta.References)
	}
}

/*
TestExternalModuleRun 验证 --execute 参数传递与输出转发。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestExternalModuleRun(t *testing.T) {
	directory := t.TempDir()
	path := writeStubModule(t, directory, "stub")

	module, err := core.NewExternalModule(path)
	if err != nil {
		t.Fatalf("加载外部模块失败: %v", err)
	}

	buffer := &bytes.Buffer{}
	options := model.Options{
		"TARGET": "example.com",
		"MODE":   "fast",
		"EMPTY":  "   ",
	}
	if err := module.Run(context.Background(), options, buffer); err != nil {
		t.Fatalf("执行外部模块失败: %v", err)
	}

	output := buffer.String()
	if !strings.Contains(output, "stub-exec") {
		t.Fatalf("缺少执行输出: %q", output)
	}
	if !strings.Contains(output, "TARGET=example.com") || !strings.Contains(output, "MODE=fast") {
		t.Fatalf("参数未正确传递: %q", output)
	}
	if strings.Contains(output, "EMPTY=") {
		t.Fatalf("空参数不应传递: %q", output)
	}
}

/*
TestExternalModuleLoad 验证目录扫描只加载可执行且元数据有效的模块。
无效脚本应产生警告而不阻止其它模块加载。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestExternalModuleLoad(t *testing.T) {
	directory := t.TempDir()
	writeStubModule(t, directory, "good")

	invalid := filepath.Join(directory, "invalid")
	if err := os.WriteFile(invalid, []byte("#!/bin/sh\necho garbage\n"), 0o755); err != nil {
		t.Fatalf("写入无效模块失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "plain.txt"), []byte("data"), 0o644); err != nil {
		t.Fatalf("写入普通文件失败: %v", err)
	}

	modules, warnings := core.LoadExternal(directory)
	if len(modules) != 1 {
		t.Fatalf("有效模块数量错误: %d", len(modules))
	}
	if len(warnings) != 1 {
		t.Fatalf("无效模块应产生 1 条警告: %v", warnings)
	}
	if !strings.Contains(warnings[0].Error(), "invalid") {
		t.Fatalf("警告内容错误: %v", warnings[0])
	}

	empty, emptyWarnings := core.LoadExternal(t.TempDir())
	if len(empty) != 0 || len(emptyWarnings) != 0 {
		t.Fatalf("空目录不应加载模块: %v %v", empty, emptyWarnings)
	}
	missing, missingWarnings := core.LoadExternal(filepath.Join(directory, "missing"))
	if len(missing) != 0 || len(missingWarnings) != 0 {
		t.Fatalf("不存在目录不应视为错误: %v %v", missing, missingWarnings)
	}
}
