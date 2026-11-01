package logger

// 日志级别，数值越小输出越详细。
const (
	LevelDebug = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

// 终端 ANSI 颜色常量。
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorCyan   = "\033[36m"
	ColorGray   = "\033[90m"
	ColorWhite  = "\033[37m"
	ColorBold   = "\033[1m"
)

// CurrentLevel 当前日志过滤级别，默认输出 Info 及以上。
var CurrentLevel = LevelInfo

// ColorEnabled 控制日志是否输出 ANSI 颜色；脚本与管道模式应关闭。
var ColorEnabled = true

/*
SetLevel 设置全局日志过滤级别。

参数:
  - level (int): 日志级别，例如 LevelDebug 或 LevelError。

返回:
  - 无。
*/
func SetLevel(level int) {
	CurrentLevel = level
}

/*
SetColor 设置日志是否输出 ANSI 颜色。

参数:
  - enabled (bool): true 表示启用颜色。

返回:
  - 无。
*/
func SetColor(enabled bool) {
	ColorEnabled = enabled
}
