// whois 模块通过 TCP 43 端口查询域名或 IP 的 WHOIS 注册信息。
package whois

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

const (
	// ianaServer 是 IANA 根 WHOIS 服务，用于发现各 TLD 的权威服务器。
	ianaServer = "whois.iana.org"

	// whoisPort 是 WHOIS 协议的标准端口。
	whoisPort = "43"

	// maxResponse 是单次 WHOIS 响应的读取上限，防止异常服务拖垮内存。
	maxResponse = 1 << 20

	// maxRawDisplay 是 RAW 模式下展示的原始字符上限。
	maxRawDisplay = 8000

	// defaultTimeout 是连接、写入与读取的总超时。
	defaultTimeout = 15 * time.Second
)

// fieldSpec 描述一组 WHOIS 键名与中文展示标签。
type fieldSpec struct {
	label string
	keys  []string
}

// fieldSpecs 是常见 WHOIS 字段的归一化规则，覆盖 gTLD 与 ccTLD 的主要写法。
var fieldSpecs = []fieldSpec{
	{label: "域名", keys: []string{"domain name", "domain", "domainname", "domain name:"}},
	{label: "注册商", keys: []string{"registrar", "sponsoring registrar", "registrar name"}},
	{label: "注册组织", keys: []string{"registrant organization", "registrant", "org", "organization"}},
	{label: "创建时间", keys: []string{"creation date", "created", "created on", "registration time", "registered on", "registration date"}},
	{label: "到期时间", keys: []string{"registry expiry date", "registrar registration expiration date", "expiration time", "expiry date", "expires", "expiration date"}},
	{label: "更新时间", keys: []string{"updated date", "last updated", "last modified", "updated"}},
	{label: "名称服务器", keys: []string{"name server", "nserver", "nameserver", "name servers"}},
	{label: "域名状态", keys: []string{"domain status", "status"}},
	{label: "DNSSEC", keys: []string{"dnssec"}},
}

// Module 是 WHOIS 查询模块。
type Module struct{}

/*
New 创建 WHOIS 查询模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回 WHOIS 查询模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "whois",
		Aliases:  []string{"domain"},
		Category: modulekit.CategoryRecon,
		Summary:  "域名或 IP 的 WHOIS 注册信息",
		Description: "通过 TCP 43 端口查询域名或 IP 的 WHOIS 注册信息并归一化展示。\n" +
			"适用于资产归属核实、注册商与到期时间调查、钓鱼域名溯源。\n" +
			"不依赖系统 whois 命令，纯 Go 实现；未指定 SERVER 时自动向 whois.iana.org\n" +
			"发现权威服务器后再查询，响应读取上限 1 MiB 防止内存失控。",
		Usage:  "use whois\nset TARGET example.com\nset RAW true\nrun",
		Author: modulekit.Author,
		Options: []model.Option{
			modulekit.Option("TARGET", "待查询的域名或 IP；自动清理协议、路径与末尾点。", true, ""),
			modulekit.Option("SERVER", "自定义 WHOIS 服务器；留空时自动向 IANA 发现权威服务器。", false, ""),
			modulekit.Option("TIMEOUT", "连接与读取总超时；支持 15s 等 Go 时长格式。", false, defaultTimeout.String()),
			modulekit.Option("RAW", "是否附加原始响应文本；取值 true/false；展示上限 8000 字符。", false, "false"),
		},
		References: []string{"https://github.com/ctkqiang/NezhaCli", "https://www.rfc-editor.org/rfc/rfc3912"},
	}
}

/*
Run 查询 WHOIS 并输出归一化字段。

参数:
  - ctx (context.Context): 查询上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 目标为空、服务器发现失败或 WHOIS 查询失败时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	target, err := normalizeTarget(options.Get("TARGET"))
	if err != nil {
		return err
	}
	timeout := options.Duration("TIMEOUT", defaultTimeout)

	server := strings.TrimSpace(options.Get("SERVER"))
	if server == "" {
		server, err = discoverServer(ctx, target, timeout)
		if err != nil {
			return err
		}
	}

	raw, err := queryServer(ctx, server, target, timeout)
	if err != nil {
		return fmt.Errorf("查询 %s 失败: %w", server, err)
	}

	modulekit.Section(out, "WHOIS · "+target)
	pairs := [][2]string{{"查询服务器", server}}
	for _, spec := range fieldSpecs {
		if value := lookupField(raw, spec.keys); value != "" {
			pairs = append(pairs, [2]string{spec.label, value})
		}
	}
	modulekit.KeyValues(out, pairs, 72)

	lower := strings.ToLower(raw)
	if strings.Contains(lower, "no match") || strings.Contains(lower, "not found") || strings.Contains(lower, "no entries found") {
		logger.Warn("WHOIS 返回未注册或未找到记录")
	}

	if options.Bool("RAW", false) {
		modulekit.Section(out, "原始响应")
		fmt.Fprintln(out, truncateRaw(filterRaw(raw)))
	}

	logger.Info("WHOIS 查询完成：%s", target)
	return nil
}

/*
normalizeTarget 清理域名或 IP 输入，去掉协议、路径与末尾点。

参数:
  - raw (string): 原始输入。

返回:
  - string: 规范化后的目标。
  - error: 输入为空时返回错误。
*/
func normalizeTarget(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("目标不能为空")
	}
	if index := strings.Index(value, "://"); index >= 0 {
		value = value[index+3:]
	}
	if index := strings.IndexAny(value, "/?#"); index >= 0 {
		value = value[:index]
	}
	if index := strings.LastIndex(value, "@"); index >= 0 {
		value = value[index+1:]
	}
	value = strings.TrimSuffix(strings.ToLower(value), ".")
	if value == "" {
		return "", fmt.Errorf("目标不能为空")
	}
	return value, nil
}

/*
discoverServer 向 IANA 查询目标的权威 WHOIS 服务器。
域名使用 TLD 查询，IP 使用完整地址查询对应 RIR。

参数:
  - ctx (context.Context): 查询上下文。
  - target (string): 域名或 IP。
  - timeout (time.Duration): 查询超时。

返回:
  - string: 权威 WHOIS 服务器域名。
  - error: 发现失败或未返回 refer 时返回错误。
*/
func discoverServer(ctx context.Context, target string, timeout time.Duration) (string, error) {
	query := target
	if net.ParseIP(target) == nil {
		if index := strings.LastIndex(target, "."); index >= 0 && index+1 < len(target) {
			query = target[index+1:]
		}
	}

	response, err := queryServer(ctx, ianaServer, query, timeout)
	if err != nil {
		return "", fmt.Errorf("查询 IANA 权威服务器失败: %w", err)
	}

	for _, line := range strings.Split(response, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "refer:") || strings.HasPrefix(lower, "whois:") {
			server := strings.TrimSpace(line[strings.Index(line, ":")+1:])
			server = strings.TrimSuffix(server, "/")
			if server != "" {
				return server, nil
			}
		}
	}
	return "", fmt.Errorf("IANA 未返回 %s 的权威 WHOIS 服务器", target)
}

/*
queryServer 向指定 WHOIS 服务器发送查询并读取响应。

参数:
  - ctx (context.Context): 查询上下文。
  - server (string): WHOIS 服务器域名。
  - query (string): 查询对象。
  - timeout (time.Duration): 总超时。

返回:
  - string: 服务器原始响应。
  - error: 连接、写入或读取失败时返回错误。
*/
func queryServer(ctx context.Context, server string, query string, timeout time.Duration) (string, error) {
	dialer := net.Dialer{Timeout: timeout}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(server, whoisPort))
	if err != nil {
		return "", err
	}
	defer connection.Close()

	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	if _, err := fmt.Fprintf(connection, "%s\r\n", query); err != nil {
		return "", err
	}

	data, err := io.ReadAll(io.LimitReader(connection, maxResponse))
	if err != nil && len(data) == 0 {
		return "", err
	}
	if len(data) == 0 {
		return "", fmt.Errorf("服务器返回空响应")
	}
	return string(data), nil
}

/*
lookupField 在 WHOIS 响应中查找一组键名对应的值。
同一键名出现多次时去重后以逗号连接。

参数:
  - raw (string): 原始 WHOIS 响应。
  - keys ([]string): 候选键名，全部小写。

返回:
  - string: 归一化后的值；未找到时返回空串。
*/
func lookupField(raw string, keys []string) string {
	wanted := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		wanted[strings.ToLower(strings.TrimSpace(strings.TrimSuffix(key, ":")))] = struct{}{}
	}

	values := make([]string, 0, 4)
	seen := make(map[string]struct{}, 4)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ">>>") {
			continue
		}
		index := strings.Index(line, ":")
		if index <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:index]))
		if _, ok := wanted[key]; !ok {
			continue
		}
		value := strings.TrimSpace(line[index+1:])
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}

	if len(values) == 0 {
		return ""
	}
	return strings.Join(values, ", ")
}

/*
filterRaw 过滤 WHOIS 原始响应中的注释与空行。

参数:
  - raw (string): 原始响应。

返回:
  - string: 过滤后的文本。
*/
func filterRaw(raw string) string {
	lines := make([]string, 0, 64)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ">>>") {
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

/*
truncateRaw 限制原始响应的展示长度。

参数:
  - raw (string): 过滤后的响应。

返回:
  - string: 截断后的文本。
*/
func truncateRaw(raw string) string {
	if len(raw) <= maxRawDisplay {
		return raw
	}
	return raw[:maxRawDisplay] + "\n…（原始响应已截断）"
}
