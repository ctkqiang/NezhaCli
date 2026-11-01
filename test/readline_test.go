package test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ctkqiang/nezha_cli/internal/readline"
)

/*
TestEditorEditing 验证行编辑器的插入、删除与光标移动。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestEditorEditing(t *testing.T) {
	editor := readline.New()
	editor.Insert('a')
	editor.Insert('b')
	editor.Insert('c')
	if editor.Line() != "abc" {
		t.Fatalf("插入错误: %q", editor.Line())
	}

	editor.MoveLeft()
	editor.Backspace()
	if editor.Line() != "ac" {
		t.Fatalf("退格错误: %q", editor.Line())
	}

	editor.MoveHome()
	editor.Insert('中')
	if editor.Line() != "中ac" {
		t.Fatalf("中文插入错误: %q", editor.Line())
	}

	editor.MoveEnd()
	editor.Backspace()
	editor.Backspace()
	if editor.Line() != "中" {
		t.Fatalf("整字退格错误: %q", editor.Line())
	}

	editor.SetLine("kill word test")
	editor.MoveEnd()
	editor.KillWordBack()
	if editor.Line() != "kill word " {
		t.Fatalf("删词错误: %q", editor.Line())
	}
}

/*
TestEditorHistory 验证历史浏览与草稿恢复。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestEditorHistory(t *testing.T) {
	editor := readline.New()
	editor.AppendHistory("show modules")
	editor.AppendHistory("use dns")
	editor.AppendHistory("")
	editor.AppendHistory("use dns")

	if len(editor.History()) != 2 {
		t.Fatalf("历史去重错误: %v", editor.History())
	}

	editor.SetLine("草稿")
	editor.HistoryUp()
	if editor.Line() != "use dns" {
		t.Fatalf("上翻错误: %q", editor.Line())
	}
	editor.HistoryUp()
	if editor.Line() != "show modules" {
		t.Fatalf("上翻错误: %q", editor.Line())
	}
	editor.HistoryDown()
	editor.HistoryDown()
	if editor.Line() != "草稿" {
		t.Fatalf("草稿恢复错误: %q", editor.Line())
	}
}

/*
TestEditorFallbackStripsArrows 验证非终端输入源会剔除方向键残留序列。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestEditorFallbackStripsArrows(t *testing.T) {
	editor := readline.New()
	writer := &bytes.Buffer{}

	line, err := editor.ReadLine(strings.NewReader("use\x1b[A\x1b[B dns\n"), writer, "nezha > ")
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if line != "use dns" {
		t.Fatalf("方向键序列未剔除: %q", line)
	}
	if !strings.Contains(writer.String(), "nezha > ") {
		t.Fatalf("提示符未输出: %q", writer.String())
	}
}
