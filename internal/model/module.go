// model 包定义哪吒战术框架的模块契约与运行参数。
package model

import (
	"context"
	"io"
	"strconv"
	"strings"
	"time"
)

// Option 描述模块的一个可配置参数。
type Option struct {
	Name        string
	Description string
	Required    bool
	Default     string
	Value       string
}

// Meta 描述模块的元数据，供控制台检索、展示与执行前校验。
type Meta struct {
	Name        string
	Aliases     []string
	Category    string
	Summary     string
	Description string
	Usage       string
	Author      string
	References  []string
	Options     []Option
	Impact      string
}

// Options 保存一次执行时用户显式设置或继承的键值参数。
type Options map[string]string

// Module 是所有内置与扩展模块必须实现的统一接口。
type Module interface {
	Meta() Meta
	Run(ctx context.Context, options Options, out io.Writer) error
}

/*
Get 读取参数值；未设置时返回空字符串。

参数:
  - key (string): 参数名称。

返回:
  - string: 参数值或空字符串。
*/
func (o Options) Get(key string) string {
	if o == nil {
		return ""
	}
	return strings.TrimSpace(o[key])
}

/*
String 读取参数值，未设置时返回回退值。

参数:
  - key (string): 参数名称。
  - fallback (string): 默认值。

返回:
  - string: 参数值或回退值。
*/
func (o Options) String(key string, fallback string) string {
	value := o.Get(key)
	if value == "" {
		return fallback
	}
	return value
}

/*
Int 读取整数参数；缺失或非法时返回回退值。

参数:
  - key (string): 参数名称。
  - fallback (int): 默认值。

返回:
  - int: 解析后的整数或回退值。
*/
func (o Options) Int(key string, fallback int) int {
	value := o.Get(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

/*
Duration 读取 Go 时长参数；缺失或非法时返回回退值。

参数:
  - key (string): 参数名称。
  - fallback (time.Duration): 默认时长。

返回:
  - time.Duration: 解析后的时长或回退值。
*/
func (o Options) Duration(key string, fallback time.Duration) time.Duration {
	value := o.Get(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

/*
Bool 读取布尔参数，支持 true/false、1/0、yes/no。

参数:
  - key (string): 参数名称。
  - fallback (bool): 默认值。

返回:
  - bool: 解析后的布尔值或回退值。
*/
func (o Options) Bool(key string, fallback bool) bool {
	switch strings.ToLower(o.Get(key)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

/*
Clone 复制参数表，避免执行过程中修改调用方的全局配置。

参数:
  - 无。

返回:
  - Options: 独立的参数副本。
*/
func (o Options) Clone() Options {
	result := make(Options, len(o))
	for key, value := range o {
		result[key] = value
	}
	return result
}
