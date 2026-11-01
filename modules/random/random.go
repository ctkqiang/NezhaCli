// random 模块使用 crypto/rand 生成战场级随机口令与令牌。
package random

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"strings"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

const (
	// charsetUpper 是大写字母集。
	charsetUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

	// charsetLower 是小写字母集。
	charsetLower = "abcdefghijklmnopqrstuvwxyz"

	// charsetDigits 是数字集。
	charsetDigits = "0123456789"

	// charsetSymbols 是常用符号集。
	charsetSymbols = "!@#$%^&*()-_=+[]{};:,.?"
)

// Module 是随机生成模块。
type Module struct{}

/*
New 创建随机生成模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回随机生成模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "random",
		Aliases:  []string{"gen", "token"},
		Category: modulekit.CategorySystem,
		Summary:  "随机口令与令牌生成",
		Description: "使用 crypto/rand 生成不可预测的口令、令牌与一次性标识。\n" +
			"适用于临时口令、Cookie 标识、API 令牌与 C2 通道随机化等场景。\n" +
			"纯 Go 实现并在本机完成，无网络依赖；字符集与数量可调，\n" +
			"拒绝采样避免取模偏差，保证每个字符均匀分布。\n" +
			"可与 crunch 配合：先生成随机口令再扩展为变形字典。",
		Usage: "use random\n" +
			"set LENGTH 24\n" +
			"set CHARSET all\n" +
			"run",
		Author: modulekit.Author,
		References: []string{
			"https://github.com/ctkqiang/NezhaCli",
			"https://www.rfc-editor.org/rfc/rfc8446",
		},
		Options: []model.Option{
			modulekit.Option("LENGTH", "单个字符串长度；范围 1-4096，超出报错", false, "16"),
			modulekit.Option("CHARSET", "字符集；取值 upper/lower/digits/symbols/hex/all", false, "all"),
			modulekit.Option("COUNT", "生成数量；范围 1-1000，超出报错", false, "1"),
		},
	}
}

/*
Run 生成并输出随机字符串。

参数:
  - ctx (context.Context): 执行上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 参数非法或随机源读取失败时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	_ = ctx

	length := options.Int("LENGTH", 16)
	if length < 1 || length > 4096 {
		return fmt.Errorf("LENGTH 需在 1-4096 之间")
	}
	count := options.Int("COUNT", 1)
	if count < 1 || count > 1000 {
		return fmt.Errorf("COUNT 需在 1-1000 之间")
	}
	charset, err := resolveCharset(options.String("CHARSET", "all"))
	if err != nil {
		return err
	}

	modulekit.Section(out, "随机生成")
	modulekit.KeyValues(out, [][2]string{
		{"长度", fmt.Sprintf("%d", length)},
		{"字符集", options.String("CHARSET", "all")},
		{"数量", fmt.Sprintf("%d", count)},
	}, 60)

	for index := 0; index < count; index++ {
		value, err := randomString(charset, length)
		if err != nil {
			return fmt.Errorf("读取随机源失败: %w", err)
		}
		fmt.Fprintf(out, "%4d. %s\n", index+1, value)
	}
	logger.Success("已生成 %d 个随机字符串", count)
	return nil
}

/*
resolveCharset 把字符集名称解析为实际字符表。

参数:
  - name (string): 字符集名称。

返回:
  - string: 实际字符表。
  - error: 名称不支持时返回错误。
*/
func resolveCharset(name string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "upper":
		return charsetUpper, nil
	case "lower":
		return charsetLower, nil
	case "digits":
		return charsetDigits, nil
	case "symbols":
		return charsetSymbols, nil
	case "hex":
		return charsetDigits + "abcdef", nil
	case "all":
		return charsetUpper + charsetLower + charsetDigits + charsetSymbols, nil
	default:
		return "", fmt.Errorf("不支持的字符集 %s，可选 upper/lower/digits/symbols/hex/all", name)
	}
}

/*
randomString 从字符表均匀采样生成随机字符串。
使用 crypto/rand 拒绝采样，避免末段字符因取模产生偏差。

参数:
  - charset (string): 字符表。
  - length (int): 目标长度。

返回:
  - string: 随机字符串。
  - error: 随机源读取失败时返回错误。
*/
func randomString(charset string, length int) (string, error) {
	builder := strings.Builder{}
	builder.Grow(length)

	// 拒绝采样上限：只接受小于 limit 的字节，避免取模偏差。
	limit := 256 - 256%len(charset)

	buffer := make([]byte, length*2)
	for builder.Len() < length {
		count, err := rand.Read(buffer)
		if err != nil && err != io.EOF {
			return "", err
		}
		for _, value := range buffer[:count] {
			if builder.Len() >= length {
				break
			}
			if int(value) >= limit {
				continue
			}
			builder.WriteByte(charset[int(value)%len(charset)])
		}
	}
	return builder.String(), nil
}
