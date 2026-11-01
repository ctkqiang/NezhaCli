// 哪吒网络安全终端入口：加载内置模块并启动战术控制台。
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ctkqiang/nezha_cli/internal/core"
	"github.com/ctkqiang/nezha_cli/internal/structure"
	"github.com/ctkqiang/nezha_cli/pkg/config"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

/*
main 解析命令行参数，加载模块注册表并进入交互控制台或脚本模式。

参数:
  - 无。

返回:
  - 无；初始化失败时以非零状态退出。
*/
func main() {
	var (
		command     string
		module      string
		externalDir string
		noColor     bool
		debug       bool
		showVersion bool
		listModules bool
	)

	flag.StringVar(&command, "c", "", "执行分号或换行分隔的控制台命令后退出")
	flag.StringVar(&module, "m", "", "启动时选中模块，例如 -m portscan")
	flag.StringVar(&externalDir, "modules", core.DefaultExternalDir, "SanTaiZi 兼容外部模块目录")
	flag.BoolVar(&noColor, "no-color", false, "禁用 ANSI 颜色")
	flag.BoolVar(&debug, "debug", false, "输出调试日志")
	flag.BoolVar(&showVersion, "version", false, "显示版本信息")
	flag.BoolVar(&listModules, "l", false, "列出全部模块后退出")
	flag.Parse()

	colorEnabled := !noColor && stdoutIsTerminal()
	logger.SetColor(colorEnabled)
	if debug {
		logger.SetLevel(logger.LevelDebug)
	}

	if showVersion {
		fmt.Printf("%s v%s\n", config.AppName, config.AppVersion)
		fmt.Printf("作者: %s\n", config.Developer)
		fmt.Printf("主页: %s\n", config.AuthorURL)
		return
	}

	registry, warnings, err := core.Load(externalDir)
	if err != nil {
		logger.Fatal("加载模块失败: %v", err)
	}
	for _, warning := range warnings {
		logger.Warn("外部模块: %v", warning)
	}

	console := structure.New(registry)
	console.SetColor(colorEnabled)

	if listModules {
		console.ExecuteOnce("show modules")
		return
	}

	if module != "" {
		if err := console.SelectModule(module); err != nil {
			logger.Fatal("%v", err)
		}
	}

	if command != "" {
		console.RunScript(command)
		if console.LastError() != nil {
			os.Exit(1)
		}
		return
	}

	if err := console.Start(); err != nil {
		logger.Fatal("控制台异常退出: %v", err)
	}
}

/*
stdoutIsTerminal 判断标准输出是否连接到终端。
管道与重定向场景会自动关闭颜色，保证脚本输出可解析。

参数:
  - 无。

返回:
  - bool: 标准输出为字符设备时返回 true。
*/
func stdoutIsTerminal() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
