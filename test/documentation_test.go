package test

import (
	"strings"
	"testing"

	"github.com/ctkqiang/nezha_cli/internal/core"
)

/*
TestModuleDocumentation 验证每个内置模块都携带完整的说明、用法、
参考与参数描述，保证 show options 与 info 能为操作员讲清用法。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestModuleDocumentation(t *testing.T) {
	registry, err := core.LoadNative()
	if err != nil {
		t.Fatalf("加载内置模块失败: %v", err)
	}

	for _, entry := range registry.List() {
		meta := entry.Meta
		name := meta.Name
		if name == "" {
			t.Fatalf("存在未命名的模块记录")
		}

		if strings.TrimSpace(meta.Summary) == "" {
			t.Errorf("%s: Summary 摘要为空", name)
		}
		if strings.TrimSpace(meta.Author) == "" {
			t.Errorf("%s: Author 作者为空", name)
		}

		description := strings.TrimSpace(meta.Description)
		if description == "" {
			t.Errorf("%s: Description 说明为空", name)
		} else if strings.Count(description, "\n") < 2 {
			t.Errorf("%s: Description 说明只有 %d 行，至少需要 3 行讲清功能、场景与注意点",
				name, strings.Count(description, "\n")+1)
		}

		usage := strings.TrimSpace(meta.Usage)
		if usage == "" {
			t.Errorf("%s: Usage 用法为空", name)
		} else if !strings.Contains(usage, "run") {
			t.Errorf("%s: Usage 用法缺少 run 示例步骤", name)
		}

		if len(meta.Aliases) == 0 {
			t.Errorf("%s: Aliases 别名列表为空", name)
		}
		if len(meta.References) < 2 {
			t.Errorf("%s: References 参考只有 %d 条，至少需要 2 条", name, len(meta.References))
		}
		for _, reference := range meta.References {
			if !strings.HasPrefix(reference, "http") {
				t.Errorf("%s: 参考链接 %q 不是合法 URL", name, reference)
			}
		}

		if len(meta.Options) == 0 {
			t.Errorf("%s: Options 参数列表为空", name)
		}
		for _, option := range meta.Options {
			if option.Name == "" || option.Name != strings.ToUpper(option.Name) {
				t.Errorf("%s: 参数名 %q 为空或不是大写", name, option.Name)
			}
			if len(strings.TrimSpace(option.Description)) < 8 {
				t.Errorf("%s: 参数 %s 的说明过短: %q", name, option.Name, option.Description)
			}
			if option.Required && option.Default != "" {
				t.Errorf("%s: 必填参数 %s 不应携带默认值", name, option.Name)
			}
		}
	}
}
