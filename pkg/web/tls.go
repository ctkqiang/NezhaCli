package web

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"
)

// TLSCertInfo 描述目标站点的 TLS 连接与证书信息。
type TLSCertInfo struct {
	Host        string
	Port        int
	TLSVersion  string
	CipherSuite string
	Subject     string
	Issuer      string
	CommonName  string
	NotBefore   time.Time
	NotAfter    time.Time
	DaysLeft    int
	Valid       bool
	Trusted     bool
	VerifyError string
	DNSNames    []string
}

/*
InspectTLS 与目标主机建立 TLS 连接并提取证书信息。
为了能够检查自签名或过期证书，握手阶段关闭默认链校验，
随后使用系统根证书单独验证并在结果中报告 Trusted 状态。

参数:
  - ctx (context.Context): 全局上下文，用于取消握手。
  - host (string): 目标主机名或 IP。
  - port (int): TLS 端口，通常为 443。
  - timeout (time.Duration): 连接与握手超时。

返回:
  - TLSCertInfo: 证书主题、签发者、有效期、信任状态与 TLS 参数。
  - error: 连接失败、握手失败或服务端未提供证书时返回错误。
*/
func InspectTLS(ctx context.Context, host string, port int, timeout time.Duration) (TLSCertInfo, error) {
	if host == "" {
		return TLSCertInfo{}, fmt.Errorf("目标主机不能为空")
	}
	if port < 1 || port > 65535 {
		return TLSCertInfo{}, fmt.Errorf("端口超出范围: %d", port)
	}

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return TLSCertInfo{}, fmt.Errorf("连接 %s 失败: %w", host, err)
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // 仅用于取证检查，信任状态由下方 Verify 单独计算
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return TLSCertInfo{}, fmt.Errorf("TLS 握手失败: %w", err)
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return TLSCertInfo{}, fmt.Errorf("服务端未提供证书")
	}
	certificate := state.PeerCertificates[0]
	now := time.Now()

	info := TLSCertInfo{
		Host:        host,
		Port:        port,
		TLSVersion:  tlsVersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		Subject:     certificate.Subject.String(),
		Issuer:      certificate.Issuer.String(),
		CommonName:  certificate.Subject.CommonName,
		NotBefore:   certificate.NotBefore,
		NotAfter:    certificate.NotAfter,
		DaysLeft:    int(certificate.NotAfter.Sub(now).Hours() / 24),
		Valid:       now.After(certificate.NotBefore) && now.Before(certificate.NotAfter),
		DNSNames:    append([]string(nil), certificate.DNSNames...),
	}

	intermediates := x509.NewCertPool()
	for _, peer := range state.PeerCertificates[1:] {
		intermediates.AddCert(peer)
	}
	verifyOptions := x509.VerifyOptions{
		DNSName:       host,
		Intermediates: intermediates,
	}
	if _, verifyErr := certificate.Verify(verifyOptions); verifyErr != nil {
		info.Trusted = false
		info.VerifyError = verifyErr.Error()
	} else {
		info.Trusted = true
	}

	return info, nil
}

/*
InspectURLTLS 从 HTTPS URL 中提取主机与端口，并执行 TLS 证书检查。

参数:
  - ctx (context.Context): 全局上下文。
  - rawURL (string): 目标 HTTPS URL。
  - timeout (time.Duration): 连接与握手超时。

返回:
  - TLSCertInfo: 证书与 TLS 参数。
  - error: URL 非法、缺少 HTTPS 或检查失败时返回错误。
*/
func InspectURLTLS(ctx context.Context, rawURL string, timeout time.Duration) (TLSCertInfo, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return TLSCertInfo{}, fmt.Errorf("URL 解析失败: %w", err)
	}
	if parsed.Scheme != "https" {
		return TLSCertInfo{}, fmt.Errorf("TLS 检查需要 https:// URL")
	}
	if parsed.Hostname() == "" {
		return TLSCertInfo{}, fmt.Errorf("URL 缺少主机名")
	}

	port := 443
	if parsed.Port() != "" {
		value, err := strconv.Atoi(parsed.Port())
		if err != nil || value < 1 || value > 65535 {
			return TLSCertInfo{}, fmt.Errorf("URL 端口非法: %s", parsed.Port())
		}
		port = value
	}

	return InspectTLS(ctx, parsed.Hostname(), port, timeout)
}

/*
tlsVersionName 将 crypto/tls 的版本常量转换为可读字符串。

参数:
  - version (uint16): TLS 协议版本常量。

返回:
  - string: 可读的 TLS 版本名称。
*/
func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("未知版本 0x%04x", version)
	}
}
