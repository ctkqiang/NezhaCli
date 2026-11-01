package main

import "nezha_cli/pkg/logger"

func main() {
	logger.SetLevel(logger.LevelInfo)

	logger.Info("哪吒网络安全系统启动成功")
}
