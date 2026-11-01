// crunch 模块用于按字符集流式生成口令字典，移植经典 crunch 思想。
package crunch

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

const (
	// maxLines 是单次生成的行数硬上限，防止误操作撑爆存储。
	maxLines = 10000000
)

// Module 是口令字典生成模块。
type Module struct{}

/*
New 创建口令字典生成模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回口令字典生成模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "crunch",
		Aliases:  []string{"wordgen", "wordlist"},
		Category: modulekit.CategorySystem,
		Summary:  "口令字典流式生成",
		Description: "按字符集与长度区间生成全排列口令字典，流式写入文件，\n" +
			"内存占用与单条口令长度成正比，不受组合总数影响。\n" +
			"LIMIT 为行数硬上限；生成中途可用 Ctrl+C 安全中止并保留已写入内容。",
		Author: modulekit.Author,
		Options: []model.Option{
			modulekit.Option("CHARSET", "候选字符集", true, ""),
			modulekit.Option("MIN", "最短长度", false, "1"),
			modulekit.Option("MAX", "最长长度", false, "4"),
			modulekit.Option("OUTPUT", "输出文件路径", true, ""),
			modulekit.Option("LIMIT", "生成行数上限；0 表示使用内置硬上限", false, "0"),
		},
	}
}

/*
Run 流式生成字典并写入输出文件。

参数:
  - ctx (context.Context): 生成上下文，Ctrl+C 时中止。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 参数非法或写入失败时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	charset := options.Get("CHARSET")
	if charset == "" {
		return fmt.Errorf("CHARSET 不能为空")
	}
	minLength := options.Int("MIN", 1)
	maxLength := options.Int("MAX", 4)
	if minLength < 1 || maxLength < minLength || maxLength > 16 {
		return fmt.Errorf("长度区间非法：MIN 需 >= 1 且 MAX 在 [MIN, 16] 之间")
	}
	limit := options.Int("LIMIT", 0)
	if limit <= 0 || limit > maxLines {
		limit = maxLines
	}

	outputPath := options.Get("OUTPUT")
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriterSize(file, 64*1024)
	defer writer.Flush()

	modulekit.Section(out, "生成配置")
	modulekit.KeyValues(out, [][2]string{
		{"字符集", charset},
		{"长度区间", fmt.Sprintf("%d-%d", minLength, maxLength)},
		{"输出", outputPath},
		{"上限", fmt.Sprintf("%d", limit)},
	}, 60)

	total, err := generate(ctx, charset, minLength, maxLength, limit, writer)
	if err != nil {
		return err
	}
	logger.Success("字典生成完成：%d 行 -> %s", total, outputPath)
	return nil
}

/*
generate 迭代长度区间并递归枚举全排列，达到上限或取消时停止。

参数:
  - ctx (context.Context): 生成上下文。
  - charset (string): 候选字符集。
  - minLength (int): 最短长度。
  - maxLength (int): 最长长度。
  - limit (int): 行数上限。
  - writer (*bufio.Writer): 缓冲写入器。

返回:
  - int: 实际写入行数。
  - error: 上下文取消时返回取消错误。
*/
func generate(ctx context.Context, charset string, minLength int, maxLength int, limit int, writer *bufio.Writer) (int, error) {
	indexes := make([]int, maxLength)
	total := 0

	for length := minLength; length <= maxLength; length++ {
		for i := 0; i < length; i++ {
			indexes[i] = 0
		}

		for {
			select {
			case <-ctx.Done():
				_ = writer.Flush()
				return total, ctx.Err()
			default:
			}

			var builder strings.Builder
			builder.Grow(length)
			for i := 0; i < length; i++ {
				builder.WriteByte(charset[indexes[i]])
			}
			if _, err := writer.WriteString(builder.String() + "\n"); err != nil {
				return total, fmt.Errorf("写入失败: %w", err)
			}
			total++
			if total >= limit {
				_ = writer.Flush()
				return total, nil
			}

			position := length - 1
			for position >= 0 {
				indexes[position]++
				if indexes[position] < len(charset) {
					break
				}
				indexes[position] = 0
				position--
			}
			if position < 0 {
				break
			}
		}
	}
	return total, nil
}
