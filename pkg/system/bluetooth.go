package system

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// BluetoothAdapter 描述一个通过 sysfs 发现的蓝牙适配器。
type BluetoothAdapter struct {
	Name    string
	Address string
	Path    string
}

/*
BluetoothAdapters 读取 /sys/class/bluetooth 下的 HCI 适配器信息。
该函数只做被动枚举，不发起蓝牙扫描、配对或连接。

参数:
  - 无。

返回:
  - []BluetoothAdapter: 按适配器名称升序排列的列表。
  - error: 无法读取蓝牙 sysfs 目录时返回错误。
*/
func BluetoothAdapters() ([]BluetoothAdapter, error) {
	const baseDir = "/sys/class/bluetooth"

	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return nil, fmt.Errorf("读取蓝牙适配器失败: %w", err)
	}

	adapters := make([]BluetoothAdapter, 0, len(entries))
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "hci") {
			continue
		}

		path := filepath.Join(baseDir, entry.Name())
		address := readTrimmedFile(filepath.Join(path, "address"))
		name := readTrimmedFile(filepath.Join(path, "name"))
		if address == "" {
			address = "未知"
		}
		if name == "" {
			name = entry.Name()
		}

		adapters = append(adapters, BluetoothAdapter{
			Name:    name,
			Address: address,
			Path:    path,
		})
	}

	sort.Slice(adapters, func(i, j int) bool {
		return adapters[i].Name < adapters[j].Name
	})
	return adapters, nil
}

/*
readTrimmedFile 读取一个小型文本文件并去除首尾空白。
读取失败时返回空字符串，便于上层使用默认值。

参数:
  - path (string): 文件路径。

返回:
  - string: 去除空白后的文件内容；读取失败时为空字符串。
*/
func readTrimmedFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
