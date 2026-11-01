// hash 模块用于战场环境的文件与数据完整性校验。
package hash

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

// Module 是哈希计算模块。
type Module struct{}

/*
New 创建哈希计算模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回哈希计算模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "hash",
		Aliases:  []string{"checksum", "digest"},
		Category: modulekit.CategorySystem,
		Summary:  "文件与数据完整性校验",
		Description: "计算文件或内联文本的 MD5/SHA1/SHA256 摘要，并可选与期望值比对。\n" +
			"适用于验证工具包、载荷与配置文件在传输或存储后未被篡改。\n" +
			"纯 Go 标准库实现，无外部依赖；INPUT 指向存在的文件时按文件读取，\n" +
			"否则按内联文本处理，EXPECT 留空时只输出计算值。\n" +
			"可与 crunch 配合：为生成的字典文件计算摘要做完整性存证。",
		Usage: "use hash\n" +
			"set INPUT /sdcard/payloads/agent.bin\n" +
			"set ALGO md5\n" +
			"set EXPECT d41d8cd98f00b204e9800998ecf8427e\n" +
			"run",
		Author: modulekit.Author,
		References: []string{
			"https://github.com/ctkqiang/NezhaCli",
			"https://www.rfc-editor.org/rfc/rfc1321",
			"https://www.rfc-editor.org/rfc/rfc6234",
		},
		Options: []model.Option{
			modulekit.Option("INPUT", "文件路径或内联文本；指向存在的文件时按文件读取，否则按文本处理", true, ""),
			modulekit.Option("ALGO", "摘要算法；取值 md5/sha1/sha256，大小写不敏感", false, "sha256"),
			modulekit.Option("EXPECT", "期望摘要；留空只输出计算值，非空则比对且忽略大小写", false, ""),
		},
	}
}

/*
Run 计算摘要并输出，可选与期望值比对。

参数:
  - ctx (context.Context): 执行上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 算法不支持或输入读取失败时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	_ = ctx

	algorithm := strings.ToLower(options.String("ALGO", "sha256"))
	digest, ok := newHash(algorithm)
	if !ok {
		return fmt.Errorf("不支持的算法 %s，可选 md5/sha1/sha256", algorithm)
	}

	input := options.Get("INPUT")
	var source string
	if info, err := os.Stat(input); err == nil && !info.IsDir() {
		file, err := os.Open(input)
		if err != nil {
			return fmt.Errorf("打开文件失败: %w", err)
		}
		defer file.Close()
		if _, err := io.Copy(digest, file); err != nil {
			return fmt.Errorf("读取文件失败: %w", err)
		}
		source = "文件 " + input
	} else {
		if _, err := io.WriteString(digest, input); err != nil {
			return fmt.Errorf("写入摘要失败: %w", err)
		}
		source = "内联文本"
	}

	sum := fmt.Sprintf("%x", digest.Sum(nil))
	modulekit.Section(out, "摘要")
	modulekit.KeyValues(out, [][2]string{
		{"算法", algorithm},
		{"来源", source},
		{"摘要", sum},
	}, 72)

	expected := strings.TrimSpace(options.Get("EXPECT"))
	if expected != "" {
		matched := strings.EqualFold(sum, strings.ToLower(expected))
		modulekit.Section(out, "校验")
		if matched {
			fmt.Fprintln(out, "校验通过：摘要与期望值一致。")
			logger.Success("完整性校验通过: %s", sum)
		} else {
			fmt.Fprintln(out, "校验失败：摘要与期望值不一致！")
			logger.Error("完整性校验失败，输入可能已被篡改")
			return fmt.Errorf("摘要不匹配")
		}
	}
	return nil
}

/*
newHash 按名称构造标准库哈希器。

参数:
  - algorithm (string): 算法名称。

返回:
  - hash.Hash: 哈希器实例。
  - bool: 算法受支持时返回 true。
*/
func newHash(algorithm string) (hash.Hash, bool) {
	switch algorithm {
	case "md5":
		return md5.New(), true
	case "sha1":
		return sha1.New(), true
	case "sha256":
		return sha256.New(), true
	default:
		return nil, false
	}
}
