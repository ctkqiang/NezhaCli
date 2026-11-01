// netutil 包提供目标解析、CIDR 展开、URL 与 MAC 规范化等网络辅助能力。
package netutil

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// MaxExpandedHosts 是单次展开的 IPv4 地址上限，避免误扫 /8 拖垮手机。
	MaxExpandedHosts = 1 << 16

	// DefaultResolveTimeout 是目标域名解析超时。
	DefaultResolveTimeout = 3 * time.Second
)

/*
SplitTargets 把逗号、分号或空白分隔的目标字符串拆分为去重列表。

参数:
  - raw (string): 原始目标字符串。

返回:
  - []string: 去重后的目标列表；空输入返回空切片。
*/
func SplitTargets(raw string) []string {
	fields := strings.FieldsFunc(raw, func(char rune) bool {
		switch char {
		case ',', ';', ' ', '\t', '\n', '\r':
			return true
		default:
			return false
		}
	})

	seen := make(map[string]struct{}, len(fields))
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		if _, exists := seen[field]; exists {
			continue
		}
		seen[field] = struct{}{}
		result = append(result, field)
	}
	return result
}

/*
ResolveTargets 把主机名、IPv4 与 CIDR 统一解析为 IPv4 CIDR 列表。
域名只保留 A 记录；IPv6 目标当前不支持，避免在无 Root 的移动端产生误导结果。

参数:
  - ctx (context.Context): 解析上下文。
  - raw (string): 逗号分隔的目标字符串。
  - limit (int): 允许展开的地址上限；小于等于 0 时使用 MaxExpandedHosts。

返回:
  - []string: 规范化后的 IPv4 CIDR 列表。
  - error: 目标为空、解析失败或范围超限时返回错误。
*/
func ResolveTargets(ctx context.Context, raw string, limit int) ([]string, error) {
	if limit <= 0 {
		limit = MaxExpandedHosts
	}

	targets := SplitTargets(raw)
	if len(targets) == 0 {
		return nil, fmt.Errorf("目标不能为空")
	}

	result := make([]string, 0, len(targets))
	total := 0
	for _, target := range targets {
		cidrs, err := resolveOne(ctx, target)
		if err != nil {
			return nil, err
		}
		for _, cidr := range cidrs {
			count, err := HostCount(cidr)
			if err != nil {
				return nil, err
			}
			total += count
			if total > limit {
				return nil, fmt.Errorf("目标地址总数超过上限 %d，请缩小扫描范围", limit)
			}
			result = append(result, cidr)
		}
	}
	return result, nil
}

/*
resolveOne 解析单个目标，返回其对应的 CIDR 列表。

参数:
  - ctx (context.Context): 解析上下文。
  - target (string): 单个主机名、IPv4 或 CIDR。

返回:
  - []string: IPv4 CIDR 列表。
  - error: 目标非法时返回错误。
*/
func resolveOne(ctx context.Context, target string) ([]string, error) {
	if strings.Contains(target, "/") {
		ip, network, err := net.ParseCIDR(target)
		if err != nil {
			return nil, fmt.Errorf("CIDR %q 非法: %w", target, err)
		}
		if ip.To4() == nil {
			return nil, fmt.Errorf("当前仅支持 IPv4 目标: %s", target)
		}
		return []string{network.String()}, nil
	}

	if ip := net.ParseIP(target); ip != nil {
		ipv4 := ip.To4()
		if ipv4 == nil {
			return nil, fmt.Errorf("当前仅支持 IPv4 目标: %s", target)
		}
		return []string{ipv4.String() + "/32"}, nil
	}

	lookupCtx, cancel := context.WithTimeout(ctx, DefaultResolveTimeout)
	defer cancel()

	addresses, err := net.DefaultResolver.LookupIP(lookupCtx, "ip4", target)
	if err != nil {
		return nil, fmt.Errorf("解析主机 %s 失败: %w", target, err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("主机 %s 没有 A 记录", target)
	}

	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		result = append(result, address.String()+"/32")
	}
	return result, nil
}

/*
HostCount 返回 CIDR 包含的地址总数，包含网络地址与广播地址。

参数:
  - cidr (string): IPv4 CIDR。

返回:
  - int: 地址总数。
  - error: CIDR 非法时返回错误。
*/
func HostCount(cidr string) (int, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, fmt.Errorf("CIDR %q 非法: %w", cidr, err)
	}
	ones, bits := network.Mask.Size()
	if bits != 32 {
		return 0, fmt.Errorf("仅支持 IPv4 CIDR: %s", cidr)
	}
	return 1 << (bits - ones), nil
}

/*
ExpandHosts 展开 CIDR 内的全部 IPv4 地址，最多返回 limit 个。

参数:
  - cidr (string): IPv4 CIDR。
  - limit (int): 返回上限；小于等于 0 时使用 MaxExpandedHosts。

返回:
  - []net.IP: 地址列表。
  - error: CIDR 非法或范围超出上限时返回错误。
*/
func ExpandHosts(cidr string, limit int) ([]net.IP, error) {
	if limit <= 0 {
		limit = MaxExpandedHosts
	}

	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("CIDR %q 非法: %w", cidr, err)
	}
	start := ip.To4()
	if start == nil {
		return nil, fmt.Errorf("仅支持 IPv4 CIDR: %s", cidr)
	}
	count, err := HostCount(cidr)
	if err != nil {
		return nil, err
	}
	if count > limit {
		return nil, fmt.Errorf("地址数量 %d 超过上限 %d", count, limit)
	}

	base := network.IP.To4()
	if base == nil {
		return nil, fmt.Errorf("仅支持 IPv4 CIDR: %s", cidr)
	}
	value := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])

	hosts := make([]net.IP, 0, count)
	for offset := 0; offset < count; offset++ {
		current := value + uint32(offset)
		hosts = append(hosts, net.IPv4(byte(current>>24), byte(current>>16), byte(current>>8), byte(current)).To4())
	}
	return hosts, nil
}

/*
JoinHostPort 拼接主机与端口，自动处理 IPv6 方括号。

参数:
  - host (string): 主机名或 IP。
  - port (int): 端口。

返回:
  - string: 可直接拨号的地址。
*/
func JoinHostPort(host string, port int) string {
	return net.JoinHostPort(strings.TrimSpace(host), strconv.Itoa(port))
}

/*
NormalizeURL 规范化用户输入的 URL；缺少协议时补 http://。

参数:
  - raw (string): 原始 URL 或主机名。
  - defaultScheme (string): 缺省协议；为空时使用 http。

返回:
  - *url.URL: 规范化后的 URL。
  - error: URL 非法或缺少主机名时返回错误。
*/
func NormalizeURL(raw string, defaultScheme string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("URL 不能为空")
	}
	if defaultScheme == "" {
		defaultScheme = "http"
	}
	if !strings.Contains(raw, "://") {
		raw = defaultScheme + "://" + raw
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("URL 解析失败: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("仅支持 http:// 或 https:// URL")
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("URL 缺少主机名")
	}
	return parsed, nil
}

/*
ParseMAC 解析 MAC 地址并校验长度必须为 6 字节。

参数:
  - value (string): 原始 MAC 字符串。

返回:
  - net.HardwareAddr: 规范化的小写 MAC。
  - error: 格式非法或长度不为 6 时返回错误。
*/
func ParseMAC(value string) (net.HardwareAddr, error) {
	address, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil {
		return nil, fmt.Errorf("MAC 地址 %q 非法: %w", value, err)
	}
	if len(address) != 6 {
		return nil, fmt.Errorf("MAC 地址必须为 6 字节: %s", value)
	}
	return address, nil
}

/*
FirstIPv4 解析主机名并返回第一个 IPv4 地址。

参数:
  - ctx (context.Context): 解析上下文。
  - host (string): 主机名或 IP。

返回:
  - string: IPv4 地址字符串。
  - error: 解析失败或没有 A 记录时返回错误。
*/
func FirstIPv4(ctx context.Context, host string) (string, error) {
	host = strings.TrimSpace(host)
	if ip := net.ParseIP(host); ip != nil {
		ipv4 := ip.To4()
		if ipv4 == nil {
			return "", fmt.Errorf("当前仅支持 IPv4 地址: %s", host)
		}
		return ipv4.String(), nil
	}

	lookupCtx, cancel := context.WithTimeout(ctx, DefaultResolveTimeout)
	defer cancel()

	addresses, err := net.DefaultResolver.LookupIP(lookupCtx, "ip4", host)
	if err != nil {
		return "", fmt.Errorf("解析主机 %s 失败: %w", host, err)
	}
	if len(addresses) == 0 {
		return "", fmt.Errorf("主机 %s 没有 A 记录", host)
	}
	return addresses[0].String(), nil
}
