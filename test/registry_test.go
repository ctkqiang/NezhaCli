package test

import (
	"strings"
	"testing"

	"github.com/ctkqiang/nezha_cli/internal/core"
	"github.com/ctkqiang/nezha_cli/internal/model"
)

/*
TestRegistryLookup 验证名称、别名、序号与大小写不敏感查找。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestRegistryLookup(t *testing.T) {
	registry := core.NewRegistry()
	module := newFakeModule(demoModuleName, "", "网络扫描演示模块")
	if err := registry.Register(module); err != nil {
		t.Fatalf("注册失败: %v", err)
	}

	for _, key := range []string{"demo", "DEMO", "demo_alias", "1"} {
		entry, ok := registry.Get(key)
		if !ok {
			t.Fatalf("Get(%q) 未命中", key)
		}
		if entry.Meta.Name != demoModuleName {
			t.Fatalf("Get(%q) 命中错误模块: %s", key, entry.Meta.Name)
		}
	}

	if _, ok := registry.Get("missing"); ok {
		t.Fatal("Get(missing) 不应命中")
	}
}

/*
TestRegistryDuplicate 验证重复模块名会被拒绝。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestRegistryDuplicate(t *testing.T) {
	registry := core.NewRegistry()
	if err := registry.Register(newFakeModule(demoModuleName, "", "第一个")); err != nil {
		t.Fatalf("首次注册失败: %v", err)
	}
	if err := registry.Register(newFakeModule(demoModuleName, "", "第二个")); err == nil {
		t.Fatal("重复注册应返回错误")
	}
}

/*
TestRegistrySearch 验证多关键词与关系检索。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestRegistrySearch(t *testing.T) {
	registry := core.NewRegistry()
	if err := registry.Register(newFakeModule("alpha", "", "网络扫描模块")); err != nil {
		t.Fatalf("注册失败: %v", err)
	}
	if err := registry.Register(newFakeModule("beta", "", "无线注入模块")); err != nil {
		t.Fatalf("注册失败: %v", err)
	}

	if results := registry.Search("网络 扫描"); len(results) != 1 || results[0].Meta.Name != "alpha" {
		t.Fatalf("多关键词检索结果错误: %+v", results)
	}
	if results := registry.Search("模块"); len(results) != 2 {
		t.Fatalf("单关键词应命中两个模块，实际 %d", len(results))
	}
	if results := registry.Search("不存在"); len(results) != 0 {
		t.Fatalf("不存在的关键词不应命中，实际 %d", len(results))
	}
}

/*
TestRegistryDefaults 验证默认参数展开。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestRegistryDefaults(t *testing.T) {
	meta := model.Meta{
		Options: []model.Option{
			{Name: "A", Default: "1"},
			{Name: "B", Default: ""},
			{Name: "C", Default: "x"},
		},
	}

	options := core.Defaults(meta)
	if len(options) != 2 {
		t.Fatalf("默认值数量错误: %d", len(options))
	}
	if options.Get("A") != "1" || options.Get("C") != "x" {
		t.Fatalf("默认值内容错误: %+v", options)
	}
	if options.Get("B") != "" {
		t.Fatalf("空默认值不应写入参数表: %+v", options)
	}
}

/*
TestRegistryCategories 验证类别去重与排序。

参数:
  - (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestRegistryCategories(t *testing.T) {
	registry := core.NewRegistry()
	first := newFakeModule("first", "", "一")
	first.meta.Category = "乙"
	second := newFakeModule("second", "", "二")
	second.meta.Category = "甲"
	third := newFakeModule("third", "", "三")
	third.meta.Category = "甲"

	for _, module := range []*fakeModule{first, second, third} {
		if err := registry.Register(module); err != nil {
			t.Fatalf("注册失败: %v", err)
		}
	}

	categories := registry.Categories()
	if strings.Join(categories, ",") != "乙,甲" {
		t.Fatalf("类别排序错误: %v", categories)
	}
}
