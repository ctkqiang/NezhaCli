package main

import (
	"nezha_cli/pkg/config"
	"nezha_cli/pkg/logger"
)

func main() {
	logger.SetLevel(logger.LevelInfo)

	logger.Info("%s启动成功", config.AppName)
}
