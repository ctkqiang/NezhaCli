package logger

import (
	"fmt"
	"os"
	"time"
)

/*
getTimeString 返回当前本地时间的时分秒字符串。

参数:
  - 无。

返回:
  - string: 形如 "15:04:05" 的时间字符串。
*/
func getTimeString() string {
	return time.Now().Format("15:04:05")
}

/*
color 在启用颜色时返回 ANSI 码，否则返回空字符串。
管道、脚本模式与 -no-color 场景下应关闭颜色，避免污染可解析输出。

参数:
  - code (string): ANSI 颜色码。

返回:
  - string: 可用颜色码或空字符串。
*/
func color(code string) string {
	if !ColorEnabled {
		return ""
	}
	return code
}

/*
Debug 输出灰色调试日志，用于底层 TCP、扫描参数与字节流追踪。

参数:
  - format (string): 格式化模板。
  - a (...interface{}): 模板参数。

返回:
  - 无。
*/
func Debug(format string, a ...interface{}) {
	if CurrentLevel <= LevelDebug {
		msg := fmt.Sprintf(format, a...)
		fmt.Printf("%s%s %s[·]%s %s\n", color(ColorGray), getTimeString(), color(ColorCyan), color(ColorReset), msg)
	}
}

/*
Info 输出绿色状态日志，用于标准状态变更与模块进度。

参数:
  - format (string): 格式化模板。
  - a (...interface{}): 模板参数。

返回:
  - 无。
*/
func Info(format string, a ...interface{}) {
	if CurrentLevel <= LevelInfo {
		msg := fmt.Sprintf(format, a...)
		fmt.Printf("%s%s %s[+]%s %s\n", color(ColorGray), getTimeString(), color(ColorGreen), color(ColorReset), msg)
	}
}

/*
Warn 输出黄色警告日志，用于非致命问题、跳过项与取消操作。

参数:
  - format (string): 格式化模板。
  - a (...interface{}): 模板参数。

返回:
  - 无。
*/
func Warn(format string, a ...interface{}) {
	if CurrentLevel <= LevelWarn {
		msg := fmt.Sprintf(format, a...)
		fmt.Printf("%s%s %s[-]%s %s%s\n", color(ColorGray), getTimeString(), color(ColorYellow), color(ColorReset), color(ColorYellow), msg+color(ColorReset))
	}
}

/*
Error 输出红色错误日志，用于局部组件故障。

参数:
  - format (string): 格式化模板。
  - a (...interface{}): 模板参数。

返回:
  - 无。
*/
func Error(format string, a ...interface{}) {
	if CurrentLevel <= LevelError {
		msg := fmt.Sprintf(format, a...)
		fmt.Fprintf(os.Stderr, "%s%s %s[!] %s%s%s\n", color(ColorGray), getTimeString(), color(ColorRed), msg, color(ColorReset), color(ColorReset))
	}
}

/*
Fatal 输出严重错误并立即退出进程。

参数:
  - format (string): 格式化模板。
  - a (...interface{}): 模板参数。

返回:
  - 无；函数会调用 os.Exit(1) 终止进程。
*/
func Fatal(format string, a ...interface{}) {
	if CurrentLevel <= LevelFatal {
		msg := fmt.Sprintf(format, a...)
		fmt.Fprintf(os.Stderr, "%s%s%s %s[FATAL] %s%s%s\n", color(ColorBold), color(ColorGray), getTimeString(), color(ColorRed), msg, color(ColorReset), color(ColorReset))
		os.Exit(1)
	}
}

/*
Success 输出高亮绿色情报日志，用于开放端口、服务指纹与关键发现。

参数:
  - format (string): 格式化模板。
  - a (...interface{}): 模板参数。

返回:
  - 无。
*/
func Success(format string, a ...interface{}) {
	if CurrentLevel <= LevelInfo {
		msg := fmt.Sprintf(format, a...)
		fmt.Printf("%s%s %s[★] %s%s%s\n", color(ColorGray), getTimeString(), color(ColorBold), color(ColorGreen), msg, color(ColorReset))
	}
}
