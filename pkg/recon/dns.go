package recon

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
)

// DNSRecord 描述一类 DNS 记录的查询结果。
type DNSRecord struct {
	Type   string
	Values []string
}

/*
LookupDNS 查询目标域名的 A、AAAA、CNAME、MX、NS 与 TXT 记录。
该函数只使用 Go 标准库解析器，不调用 dig、nslookup 等外部命令。

参数:
  - ctx (context.Context): 全局上下文，用于控制查询超时。
  - domain (string): 目标域名，例如 "example.com"。

返回:
  - []DNSRecord: 按记录类型归类的查询结果。
  - error: 域名为空或所有记录类型均查询失败时返回错误。
*/
func LookupDNS(ctx context.Context, domain string) ([]DNSRecord, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, fmt.Errorf("域名不能为空")
	}

	resolver := net.DefaultResolver
	records := make([]DNSRecord, 0, 6)
	var firstErr error

	ips, err := resolver.LookupIP(ctx, "ip", domain)
	if err != nil {
		firstErr = err
	} else {
		ipv4 := make([]string, 0, len(ips))
		ipv6 := make([]string, 0, len(ips))
		for _, ip := range ips {
			if ip.To4() != nil {
				ipv4 = append(ipv4, ip.String())
				continue
			}
			ipv6 = append(ipv6, ip.String())
		}
		records = appendDNSRecord(records, "A", ipv4)
		records = appendDNSRecord(records, "AAAA", ipv6)
	}

	cname, err := resolver.LookupCNAME(ctx, domain)
	if err == nil && cname != "" {
		records = appendDNSRecord(records, "CNAME", []string{cname})
	} else if err != nil && firstErr == nil {
		firstErr = err
	}

	mxRecords, err := resolver.LookupMX(ctx, domain)
	if err == nil {
		values := make([]string, 0, len(mxRecords))
		sort.Slice(mxRecords, func(i, j int) bool {
			return mxRecords[i].Pref < mxRecords[j].Pref
		})
		for _, mx := range mxRecords {
			values = append(values, fmt.Sprintf("%d %s", mx.Pref, mx.Host))
		}
		records = appendDNSRecord(records, "MX", values)
	} else if firstErr == nil {
		firstErr = err
	}

	nsRecords, err := resolver.LookupNS(ctx, domain)
	if err == nil {
		values := make([]string, 0, len(nsRecords))
		for _, ns := range nsRecords {
			values = append(values, ns.Host)
		}
		sort.Strings(values)
		records = appendDNSRecord(records, "NS", values)
	} else if firstErr == nil {
		firstErr = err
	}

	txtRecords, err := resolver.LookupTXT(ctx, domain)
	if err == nil {
		sort.Strings(txtRecords)
		records = appendDNSRecord(records, "TXT", txtRecords)
	} else if firstErr == nil {
		firstErr = err
	}

	if len(records) == 0 && firstErr != nil {
		return nil, fmt.Errorf("DNS 查询失败: %w", firstErr)
	}
	return records, nil
}

/*
appendDNSRecord 在值列表非空时追加一条 DNS 记录。

参数:
  - records ([]DNSRecord): 已有记录列表。
  - recordType (string): 记录类型名称。
  - values ([]string): 该类型的值列表。

返回:
  - []DNSRecord: 追加后的记录列表。
*/
func appendDNSRecord(records []DNSRecord, recordType string, values []string) []DNSRecord {
	if len(values) == 0 {
		return records
	}
	return append(records, DNSRecord{
		Type:   recordType,
		Values: values,
	})
}
