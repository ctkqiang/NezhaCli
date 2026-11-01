package core

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/model"
)

const (
	// DefaultExternalDir 是 SanTaiZi 兼容外部模块的默认目录。
	DefaultExternalDir = "modules/bin"

	// infoTimeout 是读取外部模块元数据的超时。
	infoTimeout = 5 * time.Second
)

// ExternalModule 把一个 SanTaiZi 兼容的模块二进制适配为哪吒模块。
type ExternalModule struct {
	path string
	meta model.Meta
}

/*
NewExternalModule 调用二进制 --info 读取元数据并构造适配器。
协议来源于 SanTaiZi SDK：name/description/cnvd/cve 与 option 行。

参数:
  - path (string): 模块二进制路径。

返回:
  - *ExternalModule: 外部模块适配器。
  - error: 元数据读取失败、输出为空或缺少名称时返回错误。
*/
func NewExternalModule(path string) (*ExternalModule, error) {
	ctx, cancel := context.WithTimeout(context.Background(), infoTimeout)
	defer cancel()

	command := exec.CommandContext(ctx, path, "--info")
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("读取外部模块元数据失败: %w", err)
	}

	meta, err := parseExternalInfo(string(output), filepath.Base(path))
	if err != nil {
		return nil, err
	}
	return &ExternalModule{path: path, meta: meta}, nil
}

/*
Meta 返回外部模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 归一化后的模块元数据。
*/
func (e *ExternalModule) Meta() model.Meta {
	return e.meta
}

/*
Run 以 --execute 模式运行外部模块，并把其标准输出直接写入控制台。

参数:
  - ctx (context.Context): 执行上下文，取消时会终止子进程。
  - options (model.Options): 用户参数。
  - out (io.Writer): 输出目标。

返回:
  - error: 子进程启动失败、退出码非零或执行被取消时返回错误。
*/
func (e *ExternalModule) Run(ctx context.Context, options model.Options, out io.Writer) error {
	keys := make([]string, 0, len(options))
	for key := range options {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	arguments := make([]string, 0, 1+len(keys))
	arguments = append(arguments, "--execute")
	for _, key := range keys {
		value := strings.TrimSpace(options[key])
		if value == "" {
			continue
		}
		arguments = append(arguments, key+"="+value)
	}

	command := exec.CommandContext(ctx, e.path, arguments...)
	command.Stdout = out
	command.Stderr = out
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("外部模块退出失败: %w", err)
	}
	return nil
}

/*
LoadExternal 扫描目录下的可执行文件并构造外部模块列表。
目录不存在时返回空列表，不视为错误。

参数:
  - directory (string): 外部模块目录。

返回:
  - []*ExternalModule: 成功加载的外部模块。
  - []error: 单个模块加载失败的警告列表。
*/
func LoadExternal(directory string) ([]*ExternalModule, []error) {
	if strings.TrimSpace(directory) == "" {
		return nil, nil
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, []error{fmt.Errorf("读取外部模块目录 %s 失败: %w", directory, err)}
	}

	modules := make([]*ExternalModule, 0, len(entries))
	warnings := make([]error, 0, 4)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
			continue
		}

		path := filepath.Join(directory, entry.Name())
		module, err := NewExternalModule(path)
		if err != nil {
			warnings = append(warnings, fmt.Errorf("%s: %w", entry.Name(), err))
			continue
		}
		modules = append(modules, module)
	}
	return modules, warnings
}

/*
parseExternalInfo 解析 SanTaiZi 模块 --info 输出。

参数:
  - output (string): 原始输出。
  - fallbackName (string): 缺少 name 行时使用的文件名。

返回:
  - model.Meta: 归一化后的元数据。
  - error: 输出中没有任何有效字段时返回错误。
*/
func parseExternalInfo(output string, fallbackName string) (model.Meta, error) {
	meta := model.Meta{
		Name:     fallbackName,
		Category: "外部",
		Author:   "外部模块",
		Impact:   "外部模块（执行前请确认其行为）",
	}

	valid := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}

		switch strings.ToLower(strings.TrimSpace(key)) {
		case "name":
			if value = strings.TrimSpace(value); value != "" {
				meta.Name = value
				valid = true
			}
		case "description":
			meta.Description = strings.TrimSpace(value)
			if meta.Summary == "" {
				meta.Summary = firstLine(meta.Description)
			}
		case "cnvd":
			if value = strings.TrimSpace(value); value != "" {
				meta.References = append(meta.References, "CNVD: "+value)
			}
		case "cve":
			if value = strings.TrimSpace(value); value != "" {
				meta.References = append(meta.References, "CVE: "+value)
			}
		case "option":
			option, ok := parseExternalOption(value)
			if ok {
				meta.Options = append(meta.Options, option)
			}
		}
	}

	if !valid && len(meta.Options) == 0 {
		return model.Meta{}, fmt.Errorf("外部模块未返回有效元数据")
	}
	if meta.Summary == "" {
		meta.Summary = "外部模块"
	}
	return meta, nil
}

/*
parseExternalOption 解析 SanTaiZi SDK 的 option:名称:类型:是否必填:默认值 行。
类型字段没有对应的中文说明，展示时统一标注为“类型: <值>”。

参数:
  - value (string): option 行冒号后的内容。

返回:
  - model.Option: 模块参数声明。
  - bool: 字段不足时返回 false。
*/
func parseExternalOption(value string) (model.Option, bool) {
	parts := strings.SplitN(value, ":", 4)
	if len(parts) < 4 {
		return model.Option{}, false
	}

	optionType := strings.TrimSpace(parts[1])
	description := ""
	if optionType != "" {
		description = "类型: " + optionType
	}

	return model.Option{
		Name:        strings.TrimSpace(parts[0]),
		Description: description,
		Required:    strings.EqualFold(strings.TrimSpace(parts[2]), "true"),
		Default:     strings.TrimSpace(parts[3]),
	}, true
}

/*
firstLine 返回文本的第一行，用于生成模块摘要。

参数:
  - value (string): 原始文本。

返回:
  - string: 第一行内容。
*/
func firstLine(value string) string {
	line := strings.SplitN(strings.TrimSpace(value), "\n", 2)[0]
	return strings.TrimSpace(line)
}
