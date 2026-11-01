package test

import (
	"sort"
	"strings"
	"testing"

	"github.com/ctkqiang/nezha_cli/internal/core"
	"github.com/ctkqiang/nezha_cli/internal/model"
)

// expectedModules 是内置模块的权威清单。
// 新增模块时必须同步更新该清单，防止注册遗漏或重复。
var expectedModules = []string{
	"portscan", "service", "dns", "whois", "subdomain", "lan",
	"web", "tls", "webdir", "webfinger", "payloads",
	"vecmap", "mitre", "cve",
	"cve_2025_14847", "cve_2025_4334", "cve_2025_66478",
	"connect", "http", "hash", "encode", "random", "crunch",
	"esp", "wifi_list", "wifi_scan", "wifi_deauth", "wifi_brute", "wifi_clone",
	"bt", "sysinfo",
}

// activeModules 是执行前必须通过授权确认的高影响模块。
var activeModules = []string{
	"wifi_deauth", "wifi_brute", "wifi_clone",
	"cve_2025_14847", "cve_2025_4334", "cve_2025_66478",
}

/*
TestLoadNativeCount 验证全部内置模块注册且名称唯一。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestLoadNativeCount(t *testing.T) {
	registry, err := core.LoadNative()
	if err != nil {
		t.Fatalf("加载内置模块失败: %v", err)
	}

	entries := registry.List()
	if len(entries) != len(expectedModules) {
		t.Fatalf("模块数量错误: %d，期望 %d", len(entries), len(expectedModules))
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Meta.Name)
	}
	sort.Strings(names)

	want := append([]string(nil), expectedModules...)
	sort.Strings(want)
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("模块清单不一致:\n实际: %v\n期望: %v", names, want)
	}
}

/*
TestLoadNativeMetadata 验证模块元数据完整、参数名合法且无重复。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestLoadNativeMetadata(t *testing.T) {
	registry, err := core.LoadNative()
	if err != nil {
		t.Fatalf("加载内置模块失败: %v", err)
	}

	categories := make(map[string]struct{}, 8)
	for _, entry := range registry.List() {
		meta := entry.Meta
		if strings.TrimSpace(meta.Name) == "" {
			t.Fatal("模块名称不能为空")
		}
		if strings.TrimSpace(meta.Category) == "" {
			t.Fatalf("%s 缺少类别", meta.Name)
		}
		if strings.TrimSpace(meta.Summary) == "" {
			t.Fatalf("%s 缺少摘要", meta.Name)
		}
		if strings.TrimSpace(meta.Description) == "" {
			t.Fatalf("%s 缺少说明", meta.Name)
		}
		if strings.TrimSpace(meta.Author) == "" {
			t.Fatalf("%s 缺少作者", meta.Name)
		}
		if entry.Index < 1 {
			t.Fatalf("%s 序号非法: %d", meta.Name, entry.Index)
		}
		if _, exists := categories[meta.Category]; !exists {
			categories[meta.Category] = struct{}{}
		}

		seen := make(map[string]struct{}, len(meta.Options))
		for _, option := range meta.Options {
			name := strings.ToUpper(strings.TrimSpace(option.Name))
			if name == "" {
				t.Fatalf("%s 存在空参数名", meta.Name)
			}
			if name != option.Name {
				t.Fatalf("%s 参数 %q 必须使用大写命名", meta.Name, option.Name)
			}
			if _, exists := seen[name]; exists {
				t.Fatalf("%s 参数 %s 重复", meta.Name, name)
			}
			seen[name] = struct{}{}
			if strings.TrimSpace(option.Description) == "" {
				t.Fatalf("%s 参数 %s 缺少说明", meta.Name, name)
			}
		}
	}

	if len(categories) < 5 {
		t.Fatalf("类别数量过少: %v", categories)
	}
}

/*
TestLoadNativeImpact 验证主动无线模块带有影响级别，被动模块不带。
控制台依赖 Impact 决定是否要求输入 yes 授权确认。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestLoadNativeImpact(t *testing.T) {
	registry, err := core.LoadNative()
	if err != nil {
		t.Fatalf("加载内置模块失败: %v", err)
	}

	active := make(map[string]struct{}, len(activeModules))
	for _, name := range activeModules {
		active[name] = struct{}{}

		entry, ok := registry.Get(name)
		if !ok {
			t.Fatalf("缺少主动模块 %s", name)
		}
		if strings.TrimSpace(entry.Meta.Impact) == "" {
			t.Fatalf("主动模块 %s 必须声明影响级别", name)
		}
	}

	for _, entry := range registry.List() {
		if _, isActive := active[entry.Meta.Name]; isActive {
			continue
		}
		if entry.Meta.Impact != "" {
			t.Fatalf("被动模块 %s 不应声明影响级别: %s", entry.Meta.Name, entry.Meta.Impact)
		}
	}
}

/*
TestLoadNativeSearch 验证按中文类别检索无线模块。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestLoadNativeSearch(t *testing.T) {
	registry, err := core.LoadNative()
	if err != nil {
		t.Fatalf("加载内置模块失败: %v", err)
	}

	results := registry.Search("无线")
	if len(results) != 6 {
		t.Fatalf("无线模块数量错误: %d", len(results))
	}

	web := registry.Search("web")
	if len(web) < 3 {
		t.Fatalf("Web 检索结果过少: %d", len(web))
	}
	if len(registry.Search("不存在的关键词")) != 0 {
		t.Fatal("不存在的关键词不应命中")
	}
}

/*
TestLoadDefaultsAndRegistry 验证外部目录不存在时仍能启动且不产生警告。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestLoadDefaultsAndRegistry(t *testing.T) {
	registry, warnings, err := core.Load(t.TempDir())
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("空目录不应产生警告: %v", warnings)
	}
	if len(registry.List()) != len(expectedModules) {
		t.Fatalf("模块数量错误: %d", len(registry.List()))
	}

	entry, ok := registry.Get("portscan")
	if !ok {
		t.Fatal("缺少 portscan 模块")
	}
	options := core.Defaults(entry.Meta)
	if options.Get("PORTS") == "" || options.Get("WORKERS") == "" {
		t.Fatalf("默认参数未展开: %+v", options)
	}
}

/*
TestLoadNativeIndependent 验证两次加载返回互相独立的注册表。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestLoadNativeIndependent(t *testing.T) {
	first, err := core.LoadNative()
	if err != nil {
		t.Fatalf("首次加载失败: %v", err)
	}
	second, err := core.LoadNative()
	if err != nil {
		t.Fatalf("第二次加载失败: %v", err)
	}

	if err := first.Register(newFakeModule("extra", "", "额外模块")); err != nil {
		t.Fatalf("注册失败: %v", err)
	}
	if _, ok := second.Get("extra"); ok {
		t.Fatal("两个注册表不应共享状态")
	}
}

/*
TestModuleOptionsParsing 验证模块参数类型读取的容错行为。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestModuleOptionsParsing(t *testing.T) {
	options := model.Options{
		"INT":      "42",
		"BAD_INT":  "abc",
		"DURATION": "1500ms",
		"BAD_DUR":  "soon",
		"BOOL":     "yes",
		"FALSE":    "off",
		"SPACE":    "  value  ",
	}

	if got := options.Int("INT", 0); got != 42 {
		t.Fatalf("Int 解析错误: %d", got)
	}
	if got := options.Int("BAD_INT", 7); got != 7 {
		t.Fatalf("非法 Int 应回落: %d", got)
	}
	if got := options.Duration("DURATION", 0); got.String() != "1.5s" {
		t.Fatalf("Duration 解析错误: %s", got)
	}
	if got := options.Duration("BAD_DUR", 3); got != 3 {
		t.Fatalf("非法 Duration 应回落: %s", got)
	}
	if !options.Bool("BOOL", false) {
		t.Fatal("yes 应解析为 true")
	}
	if options.Bool("FALSE", true) {
		t.Fatal("off 应解析为 false")
	}
	if got := options.Get("SPACE"); got != "value" {
		t.Fatalf("Get 应去除首尾空白: %q", got)
	}
	if got := options.String("MISSING", "fallback"); got != "fallback" {
		t.Fatalf("String 回落错误: %q", got)
	}

	clone := options.Clone()
	clone["INT"] = "1"
	if options.Get("INT") != "42" {
		t.Fatal("Clone 不应修改原参数表")
	}
}
