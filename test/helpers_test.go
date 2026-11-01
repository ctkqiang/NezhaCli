package test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/ctkqiang/nezha_cli/internal/core"
	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/structure"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

const (
	// demoModuleName 是测试用模块名。
	demoModuleName = "demo"

	// activeModuleName 是带影响级别的测试模块名。
	activeModuleName = "demo_active"

	// testCategory 是测试模块类别。
	testCategory = "测试"
)

// fakeModule 是用于注册表与控制台测试的假模块。
type fakeModule struct {
	meta model.Meta
	err  error
}

/*
TestMain 关闭测试期间的日志颜色与信息输出，保持断言输出干净。

参数:
  - m (*testing.M): Go 测试入口。

返回:
  - 无。
*/
func TestMain(m *testing.M) {
	logger.SetColor(false)
	logger.SetLevel(logger.LevelError)
	os.Exit(m.Run())
}

/*
Meta 返回假模块元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块元数据。
*/
func (f *fakeModule) Meta() model.Meta {
	return f.meta
}

/*
Run 把收到的 VALUE 参数写入输出目标。

参数:
  - ctx (context.Context): 执行上下文。
  - options (model.Options): 模块参数。
  - out (io.Writer): 输出目标。

返回:
  - error: 假模块预设的错误。
*/
func (f *fakeModule) Run(ctx context.Context, options model.Options, out io.Writer) error {
	_ = ctx
	fmt.Fprintf(out, "fake-output VALUE=%s\n", options.Get("VALUE"))
	return f.err
}

/*
newFakeModule 构造一个带 VALUE 参数的假模块。

参数:
  - name (string): 模块名。
  - impact (string): 影响级别。
  - description (string): 模块说明。

返回:
  - *fakeModule: 假模块。
*/
func newFakeModule(name string, impact string, description string) *fakeModule {
	return &fakeModule{
		meta: model.Meta{
			Name:        name,
			Aliases:     []string{name + "_alias"},
			Category:    testCategory,
			Summary:     description,
			Description: description,
			Author:      "测试",
			Impact:      impact,
			Options: []model.Option{
				{Name: "VALUE", Description: "测试参数", Required: false, Default: "default"},
			},
		},
	}
}

/*
newSensitiveConsole 构造包含 PASSWORD 参数的假模块注册表。
用于验证控制台展示阶段对凭证类参数的脱敏行为。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - *core.Registry: 只含敏感参数模块的注册表。
  - *bytes.Buffer: 输出缓冲。
*/
func newSensitiveConsole(t *testing.T) (*core.Registry, *bytes.Buffer) {
	t.Helper()

	module := newFakeModule("secret_demo", "", "凭证展示测试")
	module.meta.Options = []model.Option{
		{Name: "PASSWORD", Description: "测试密码", Required: false, Default: ""},
	}

	registry := core.NewRegistry()
	if err := registry.Register(module); err != nil {
		t.Fatalf("注册 secret_demo 失败: %v", err)
	}
	return registry, &bytes.Buffer{}
}

/*
newConsole 创建注册了假模块的控制台，并捕获全部输出。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - *structure.Console: 控制台。
  - *bytes.Buffer: 输出缓冲。
  - *core.Registry: 注册表。
*/
func newConsole(t *testing.T) (*structure.Console, *bytes.Buffer, *core.Registry) {
	t.Helper()

	registry := core.NewRegistry()
	if err := registry.Register(newFakeModule(demoModuleName, "", "网络扫描演示模块")); err != nil {
		t.Fatalf("注册 demo 模块失败: %v", err)
	}
	if err := registry.Register(newFakeModule(activeModuleName, "高（测试影响）", "主动测试模块")); err != nil {
		t.Fatalf("注册 active 模块失败: %v", err)
	}

	buffer := &bytes.Buffer{}
	console := structure.New(registry)
	console.SetColor(false)
	console.SetOutput(buffer)
	return console, buffer, registry
}
