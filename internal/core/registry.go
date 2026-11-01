// core 包维护模块注册表与加载器，是控制台与具体能力之间的唯一边界。
package core

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/ctkqiang/nezha_cli/internal/model"
)

// Entry 是注册表中的一条模块记录。
type Entry struct {
	Index  int
	Module model.Module
	Meta   model.Meta
}

/*
NewRegistry 创建一个空的模块注册表。

参数:
  - 无。

返回:
  - *Registry: 可直接注册模块的注册表。
*/
func NewRegistry() *Registry {
	return &Registry{
		entries: make([]*Entry, 0, 32),
		byName:  make(map[string]*Entry, 32),
	}
}

// Registry 保存全部可用模块，并保证名称与别名唯一。
type Registry struct {
	mu      sync.RWMutex
	entries []*Entry
	byName  map[string]*Entry
}

/*
Register 注册一个模块，并为其分配稳定索引。
同一模块被重复注册时只保留第一次，避免扩展目录与内置模块互相覆盖。

参数:
  - module (model.Module): 待注册模块。

返回:
  - error: 模块名称为空或与现有别名冲突时返回错误。
*/
func (r *Registry) Register(module model.Module) error {
	if module == nil {
		return fmt.Errorf("模块不能为空")
	}

	meta := module.Meta()
	name := strings.TrimSpace(meta.Name)
	if name == "" {
		return fmt.Errorf("模块名称不能为空")
	}
	meta.Name = name

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.byName[strings.ToLower(name)]; exists {
		return fmt.Errorf("模块 %s 已注册", name)
	}

	entry := &Entry{
		Index:  len(r.entries) + 1,
		Module: module,
		Meta:   meta,
	}
	r.entries = append(r.entries, entry)
	r.byName[strings.ToLower(name)] = entry
	for _, alias := range meta.Aliases {
		alias = strings.TrimSpace(alias)
		if alias == "" {
			continue
		}
		key := strings.ToLower(alias)
		if _, exists := r.byName[key]; !exists {
			r.byName[key] = entry
		}
	}
	return nil
}

/*
List 返回按注册顺序排列的全部模块。

参数:
  - 无。

返回:
  - []*Entry: 模块记录切片，调用方不得修改切片内容。
*/
func (r *Registry) List() []*Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*Entry, len(r.entries))
	copy(result, r.entries)
	return result
}

/*
Get 按名称、别名或序号查找模块。

参数:
  - key (string): 模块名、别名或注册序号。

返回:
  - *Entry: 命中的模块记录。
  - bool: 未命中时返回 false。
*/
func (r *Registry) Get(key string) (*Entry, bool) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if entry, ok := r.byName[strings.ToLower(key)]; ok {
		return entry, true
	}
	for _, entry := range r.entries {
		if fmt.Sprintf("%d", entry.Index) == key {
			return entry, true
		}
	}
	return nil, false
}

/*
Search 按关键词检索模块名称、别名、类别、摘要与描述。
多个关键词之间是“与”关系，必须全部命中才会返回。

参数:
  - keyword (string): 以空格分隔的检索词。

返回:
  - []*Entry: 命中的模块记录，保持注册顺序。
*/
func (r *Registry) Search(keyword string) []*Entry {
	terms := strings.Fields(strings.ToLower(keyword))
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(terms) == 0 {
		result := make([]*Entry, len(r.entries))
		copy(result, r.entries)
		return result
	}

	result := make([]*Entry, 0, 8)
	for _, entry := range r.entries {
		haystack := strings.ToLower(strings.Join([]string{
			entry.Meta.Name,
			strings.Join(entry.Meta.Aliases, " "),
			entry.Meta.Category,
			entry.Meta.Summary,
			entry.Meta.Description,
			entry.Meta.Usage,
		}, " "))

		matched := true
		for _, term := range terms {
			if !strings.Contains(haystack, term) {
				matched = false
				break
			}
		}
		if matched {
			result = append(result, entry)
		}
	}
	return result
}

/*
Categories 返回注册表中出现的全部类别，按字典序排列。

参数:
  - 无。

返回:
  - []string: 去重后的类别列表。
*/
func (r *Registry) Categories() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := make(map[string]struct{}, 8)
	for _, entry := range r.entries {
		if entry.Meta.Category != "" {
			seen[entry.Meta.Category] = struct{}{}
		}
	}

	result := make([]string, 0, len(seen))
	for category := range seen {
		result = append(result, category)
	}
	sort.Strings(result)
	return result
}

/*
Defaults 把模块声明的默认参数展开为参数表。

参数:
  - meta (model.Meta): 模块元数据。

返回:
  - model.Options: 包含全部默认值的参数表。
*/
func Defaults(meta model.Meta) model.Options {
	options := make(model.Options, len(meta.Options))
	for _, option := range meta.Options {
		if option.Default != "" {
			options[option.Name] = option.Default
		}
	}
	return options
}
