package test

import (
	"strings"
	"testing"

	"github.com/ctkqiang/nezha_cli/internal/structure"
)

/*
TestConsoleQuotedSet 验证带空格的值可以通过双引号写入参数表并传给模块。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestConsoleQuotedSet(t *testing.T) {
	console, buffer, _ := newConsole(t)

	console.Execute("use demo")
	console.Execute(`set VALUE "hello world"`)
	console.Execute("run")

	output := buffer.String()
	if !strings.Contains(output, "VALUE=hello world") {
		t.Fatalf("模块未收到完整参数:\n%s", output)
	}
	if !strings.Contains(output, "VALUE = hello world") {
		t.Fatalf("缺少设置确认:\n%s", output)
	}
}

/*
TestConsoleSessions 验证执行记录包含模块名、状态与耗时。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestConsoleSessions(t *testing.T) {
	console, buffer, _ := newConsole(t)

	console.Execute("use demo")
	console.Execute("run")
	console.Execute("sessions")

	output := buffer.String()
	if !strings.Contains(output, "执行记录") {
		t.Fatalf("缺少执行记录标题:\n%s", output)
	}
	if !strings.Contains(output, "demo") || !strings.Contains(output, "成功") {
		t.Fatalf("执行记录内容错误:\n%s", output)
	}
}

/*
TestConsoleSessionsEmpty 验证未执行任何模块时的提示。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestConsoleSessionsEmpty(t *testing.T) {
	console, buffer, _ := newConsole(t)
	console.Execute("sessions")

	if !strings.Contains(buffer.String(), "还没有执行记录") {
		t.Fatalf("缺少空记录提示:\n%s", buffer.String())
	}
}

/*
TestConsoleSearch 验证关键词检索与空关键词回退。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestConsoleSearch(t *testing.T) {
	console, buffer, _ := newConsole(t)

	console.Execute("search 扫描")
	if !strings.Contains(buffer.String(), "demo") {
		t.Fatalf("检索未命中 demo:\n%s", buffer.String())
	}
	if strings.Contains(buffer.String(), "demo_active") {
		t.Fatalf("无关模块不应命中:\n%s", buffer.String())
	}

	buffer.Reset()
	console.Execute("search")
	if !strings.Contains(buffer.String(), "未提供关键词") {
		t.Fatalf("空关键词缺少提示:\n%s", buffer.String())
	}
	if !strings.Contains(buffer.String(), "demo") || !strings.Contains(buffer.String(), "demo_active") {
		t.Fatalf("空关键词应展示全部模块:\n%s", buffer.String())
	}
}

/*
TestConsoleAuthorizationRejected 验证主动模块在未输入 yes 时不会执行。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestConsoleAuthorizationRejected(t *testing.T) {
	for _, answer := range []string{"no\n", "\n", "YES!\n"} {
		console, buffer, _ := newConsole(t)
		console.SetInput(strings.NewReader(answer))

		console.Execute("use demo_active")
		console.Execute("run")

		output := buffer.String()
		if strings.Contains(output, "fake-output") {
			t.Fatalf("输入 %q 时模块不应执行:\n%s", answer, output)
		}
		if !strings.Contains(output, "授权确认") {
			t.Fatalf("缺少授权确认提示:\n%s", output)
		}
		if !strings.Contains(output, "操作已取消") {
			t.Fatalf("缺少取消提示:\n%s", output)
		}
	}
}

/*
TestConsoleAuthorizationAccepted 验证输入 yes 后主动模块会执行并记录会话。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestConsoleAuthorizationAccepted(t *testing.T) {
	console, buffer, _ := newConsole(t)
	console.SetInput(strings.NewReader("yes\n"))

	console.Execute("use demo_active")
	console.Execute("run")
	console.Execute("sessions")

	output := buffer.String()
	if !strings.Contains(output, "fake-output") {
		t.Fatalf("确认授权后模块应执行:\n%s", output)
	}
	if !strings.Contains(output, "demo_active") {
		t.Fatalf("执行记录缺少模块名:\n%s", output)
	}
}

/*
TestConsoleRunScript 验证脚本模式的拆分、引号内分号与退出语义。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestConsoleRunScript(t *testing.T) {
	console, buffer, _ := newConsole(t)

	if !console.RunScript(`use demo; set VALUE "a;b"; run`) {
		t.Fatal("脚本不应要求退出")
	}
	if !strings.Contains(buffer.String(), "VALUE=a;b") {
		t.Fatalf("引号内分号被错误拆分:\n%s", buffer.String())
	}

	if console.RunScript("history\nexit\nshow modules") {
		t.Fatal("脚本包含 exit 时应返回 false")
	}
	if strings.Contains(buffer.String(), "模块 2") {
		t.Fatalf("exit 之后的命令不应执行:\n%s", buffer.String())
	}
}

/*
TestConsoleExit 验证 exit/quit 返回退出信号，空行则继续运行。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestConsoleExit(t *testing.T) {
	console, _, _ := newConsole(t)

	if !console.Execute("") {
		t.Fatal("空行不应退出")
	}
	if !console.Execute("help") {
		t.Fatal("help 不应退出")
	}
	for _, command := range []string{"exit", "quit", "q"} {
		if console.Execute(command) {
			t.Fatalf("%s 应要求退出", command)
		}
	}
}

/*
TestConsoleBack 验证取消选择后 run 不再执行模块。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestConsoleBack(t *testing.T) {
	console, buffer, _ := newConsole(t)

	console.Execute("use demo")
	console.Execute("back")
	buffer.Reset()
	console.Execute("run")

	output := buffer.String()
	if strings.Contains(output, "fake-output") {
		t.Fatalf("back 之后不应执行模块:\n%s", output)
	}
	if !strings.Contains(output, "尚未选择模块") {
		t.Fatalf("缺少未选择提示:\n%s", output)
	}
}

/*
TestConsoleSetValidation 验证未知参数、未选择模块与 setg 覆盖行为。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestConsoleSetValidation(t *testing.T) {
	console, buffer, _ := newConsole(t)

	console.Execute("set VALUE x")
	if !strings.Contains(buffer.String(), "全局参数请使用 setg") {
		t.Fatalf("未选择模块时应提示 setg:\n%s", buffer.String())
	}

	buffer.Reset()
	console.Execute("use demo")
	console.Execute("set UNKNOWN x")
	if !strings.Contains(buffer.String(), "没有参数 UNKNOWN") {
		t.Fatalf("未知参数应被拒绝:\n%s", buffer.String())
	}

	buffer.Reset()
	console.Execute("setg VALUE global")
	console.Execute("use demo_active")
	console.Execute("show options")
	if !strings.Contains(buffer.String(), "global") {
		t.Fatalf("全局参数未覆盖模块参数:\n%s", buffer.String())
	}
}

/*
TestConsoleSelectModule 验证启动参数选择模块的路径。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestConsoleSelectModule(t *testing.T) {
	console, buffer, _ := newConsole(t)

	if err := console.SelectModule("demo_alias"); err != nil {
		t.Fatalf("按别名选择失败: %v", err)
	}
	console.Execute("info")
	if !strings.Contains(buffer.String(), "模块 · demo") {
		t.Fatalf("模块卡片错误:\n%s", buffer.String())
	}

	if err := console.SelectModule("missing"); err == nil {
		t.Fatal("不存在的模块应返回错误")
	}
}

/*
TestConsoleHistory 与 TestConsoleEnv 验证历史与参数总览。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestConsoleHistoryAndEnv(t *testing.T) {
	console, buffer, _ := newConsole(t)

	console.Execute("use demo")
	console.Execute("set VALUE secret")
	console.Execute("history")

	output := buffer.String()
	if !strings.Contains(output, "命令历史") || !strings.Contains(output, "use demo") {
		t.Fatalf("历史记录错误:\n%s", output)
	}

	buffer.Reset()
	console.Execute("env")
	if !strings.Contains(buffer.String(), "当前模块参数") {
		t.Fatalf("env 缺少当前模块参数:\n%s", buffer.String())
	}
}

/*
TestConsoleSensitiveOption 验证敏感参数在展示时被脱敏。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestConsoleSensitiveOption(t *testing.T) {
	registry, buffer := newSensitiveConsole(t)

	console := structure.New(registry)
	console.SetColor(false)
	console.SetOutput(buffer)
	console.Execute("use secret_demo")
	console.Execute("set PASSWORD hunter2")
	buffer.Reset()
	console.Execute("show options")

	output := buffer.String()
	if strings.Contains(output, "hunter2") {
		t.Fatalf("敏感参数不应明文展示:\n%s", output)
	}
	if !strings.Contains(output, "********") {
		t.Fatalf("敏感参数应显示占位符:\n%s", output)
	}
}

/*
TestConsoleOptionsAlias 验证 options / option 简写与 show options 等价。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestConsoleOptionsAlias(t *testing.T) {
	console, buffer, _ := newConsole(t)
	console.Execute("use demo")

	buffer.Reset()
	console.Execute("options")
	if !strings.Contains(buffer.String(), "模块参数") {
		t.Fatalf("options 简写应展示参数表:\n%s", buffer.String())
	}

	buffer.Reset()
	console.Execute("option")
	if !strings.Contains(buffer.String(), "模块参数") {
		t.Fatalf("option 简写应展示参数表:\n%s", buffer.String())
	}

	buffer.Reset()
	console.Execute("show info")
	if !strings.Contains(buffer.String(), "模块 · demo") {
		t.Fatalf("show info 应展示模块卡片:\n%s", buffer.String())
	}
}

/*
TestConsoleShellFallback 验证未识别命令会交给系统 shell 执行。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestConsoleShellFallback(t *testing.T) {
	console, buffer, _ := newConsole(t)

	console.Execute("printf shell-ok")
	if !strings.Contains(buffer.String(), "shell-ok") {
		t.Fatalf("未识别命令应通过 shell 执行:\n%s", buffer.String())
	}

	buffer.Reset()
	console.Execute("command-does-not-exist-xyz")
	if !strings.Contains(buffer.String(), "退出状态") {
		t.Fatalf("shell 命令失败应提示退出状态:\n%s", buffer.String())
	}
}
