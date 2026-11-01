// encode 模块用于载荷的 base64/hex/URL 编解码。
package encode

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

// Module 是编解码模块。
type Module struct{}

/*
New 创建编解码模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回编解码模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "encode",
		Aliases:  []string{"b64", "base64"},
		Category: modulekit.CategorySystem,
		Summary:  "载荷 base64 / hex / URL 编解码",
		Description: "对载荷文本执行 base64、hex 或 URL 编码与解码，\n" +
			"覆盖战场常见的数据转换需求；hex 解码输出原始字节转义预览。",
		Author: modulekit.Author,
		Options: []model.Option{
			modulekit.Option("ACTION", "encode 或 decode", false, "encode"),
			modulekit.Option("ALGO", "base64 / hex / url", false, "base64"),
			modulekit.Option("VALUE", "待处理文本", true, ""),
		},
	}
}

/*
Run 执行编解码并输出结果。

参数:
  - ctx (context.Context): 执行上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 算法不支持或解码输入非法时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	_ = ctx

	action := strings.ToLower(options.String("ACTION", "encode"))
	algorithm := strings.ToLower(options.String("ALGO", "base64"))
	value := options.Get("VALUE")

	var result string
	var err error
	if action == "encode" {
		result, err = encodeValue(algorithm, value)
	} else if action == "decode" {
		result, err = decodeValue(algorithm, value)
	} else {
		return fmt.Errorf("ACTION 只能是 encode 或 decode")
	}
	if err != nil {
		return err
	}

	modulekit.Section(out, "结果")
	modulekit.KeyValues(out, [][2]string{
		{"动作", action},
		{"算法", algorithm},
		{"输入", modulekit.Etc(value, 56)},
		{"输出", modulekit.Etc(result, 72)},
	}, 72)
	logger.Info("编解码完成：%s %s", action, algorithm)
	return nil
}

/*
encodeValue 按算法编码文本。

参数:
  - algorithm (string): base64 / hex / url。
  - value (string): 原始文本。

返回:
  - string: 编码结果。
  - error: 算法不支持时返回错误。
*/
func encodeValue(algorithm string, value string) (string, error) {
	switch algorithm {
	case "base64":
		return base64.StdEncoding.EncodeToString([]byte(value)), nil
	case "hex":
		return hex.EncodeToString([]byte(value)), nil
	case "url":
		return url.QueryEscape(value), nil
	default:
		return "", fmt.Errorf("不支持的算法 %s，可选 base64/hex/url", algorithm)
	}
}

/*
decodeValue 按算法解码文本。

参数:
  - algorithm (string): base64 / hex / url。
  - value (string): 编码文本。

返回:
  - string: 解码结果；hex 输出附原始字节预览。
  - error: 解码输入非法时返回错误。
*/
func decodeValue(algorithm string, value string) (string, error) {
	switch algorithm {
	case "base64":
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return "", fmt.Errorf("base64 解码失败: %w", err)
		}
		return string(decoded), nil
	case "hex":
		decoded, err := hex.DecodeString(strings.ReplaceAll(value, " ", ""))
		if err != nil {
			return "", fmt.Errorf("hex 解码失败: %w", err)
		}
		return fmt.Sprintf("%q (原始 %d 字节)", string(decoded), len(decoded)), nil
	case "url":
		decoded, err := url.QueryUnescape(value)
		if err != nil {
			return "", fmt.Errorf("URL 解码失败: %w", err)
		}
		return decoded, nil
	default:
		return "", fmt.Errorf("不支持的算法 %s，可选 base64/hex/url", algorithm)
	}
}
