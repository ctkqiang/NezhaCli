// engine 包负责校验模块参数、执行模块并记录运行结果。
package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/core"
	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

// Result 记录一次模块执行的结果摘要，供控制台会话列表展示。
type Result struct {
	Module   string
	Started  time.Time
	Duration time.Duration
	Err      error
}

/*
Validate 校验必填参数，并把缺失项汇总成一条可操作的错误。
校验只检查“有没有填”，具体格式由各模块自行解析并给出领域错误。

参数:
  - entry (*core.Entry): 待执行模块。
  - options (model.Options): 当前参数表。

返回:
  - error: 存在缺失必填参数时返回错误。
*/
func Validate(entry *core.Entry, options model.Options) error {
	missing := make([]string, 0, len(entry.Meta.Options))
	for _, option := range entry.Meta.Options {
		if option.Required && options.Get(option.Name) == "" {
			missing = append(missing, option.Name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("缺少必填参数: %s（使用 set %s <值> 配置）",
		strings.Join(missing, ", "), missing[0])
}

/*
Run 在统一日志与错误边界内执行模块。
执行前会合并模块默认值，执行后输出耗时；取消不会被视为模块故障。
模块内部发生 panic 时会被恢复并转换为错误，保证控制台永不崩溃。

参数:
  - ctx (context.Context): 全局上下文，用于 Ctrl+C 取消。
  - entry (*core.Entry): 待执行模块。
  - options (model.Options): 用户参数。
  - out (io.Writer): 模块数据输出目标。

返回:
  - Result: 执行摘要。
  - error: 参数缺失、取消、模块错误或 panic 时返回错误。
*/
func Run(ctx context.Context, entry *core.Entry, options model.Options, out io.Writer) (result Result, err error) {
	result = Result{
		Module:  entry.Meta.Name,
		Started: time.Now(),
	}

	merged := core.Defaults(entry.Meta)
	for key, value := range options {
		if strings.TrimSpace(value) != "" {
			merged[key] = value
		}
	}

	if validateErr := Validate(entry, merged); validateErr != nil {
		result.Err = validateErr
		return result, validateErr
	}

	logger.Info("启动模块 %s · 类别 %s", entry.Meta.Name, entry.Meta.Category)
	if entry.Meta.Impact != "" {
		logger.Warn("影响级别: %s", entry.Meta.Impact)
	}

	err = runSafely(entry, ctx, merged, out)
	result.Duration = time.Since(result.Started)
	result.Err = err

	switch {
	case err == nil:
		logger.Success("模块 %s 执行完成，耗时 %s", entry.Meta.Name, result.Duration.Round(time.Millisecond))
	case errors.Is(err, context.Canceled):
		logger.Warn("模块 %s 已被操作员中止", entry.Meta.Name)
	default:
		logger.Error("模块 %s 失败: %v", entry.Meta.Name, err)
	}

	return result, err
}

/*
runSafely 在 recover 保护下调用模块 Run。
战场环境强调“一个模块崩溃不能带走整台控制台”：
任何 panic 都会被转换为可记录的 error，而不是击穿进程。

参数:
  - entry (*core.Entry): 待执行模块。
  - ctx (context.Context): 全局上下文。
  - merged (model.Options): 已合并默认值的参数表。
  - out (io.Writer): 模块数据输出目标。

返回:
  - error: 模块返回的错误或 panic 转换后的错误。
*/
func runSafely(entry *core.Entry, ctx context.Context, merged model.Options, out io.Writer) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("模块内部 panic: %v", recovered)
		}
	}()
	return entry.Module.Run(ctx, merged, out)
}
