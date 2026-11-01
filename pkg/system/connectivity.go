package system

import (
	"context"
	"fmt"
	"net"
	"time"
)

// ConnectivityResult 描述一次外网 TCP 连通性探测结果。
type ConnectivityResult struct {
	Target  string
	OK      bool
	Latency time.Duration
	Error   string
}

/*
CheckConnectivity 依次对目标 TCP 端点执行带超时的连通性探测。
该函数用于判断当前网络是否允许出站连接，不发送任何应用层数据。

参数:
  - ctx (context.Context): 全局上下文，用于整体取消。
  - targets ([]string): 形如 "1.1.1.1:53" 的 TCP 目标列表。
  - timeout (time.Duration): 单个目标的连接超时。

返回:
  - []ConnectivityResult: 与 targets 顺序一致的探测结果。
*/
func CheckConnectivity(ctx context.Context, targets []string, timeout time.Duration) []ConnectivityResult {
	results := make([]ConnectivityResult, 0, len(targets))
	for _, target := range targets {
		start := time.Now()
		dialer := net.Dialer{Timeout: timeout}
		conn, err := dialer.DialContext(ctx, "tcp", target)
		latency := time.Since(start)

		if err != nil {
			results = append(results, ConnectivityResult{
				Target:  target,
				OK:      false,
				Latency: latency,
				Error:   err.Error(),
			})
			continue
		}
		_ = conn.Close()
		results = append(results, ConnectivityResult{
			Target:  target,
			OK:      true,
			Latency: latency,
		})
	}
	return results
}

/*
FormatConnectivity 将连通性结果格式化为适合终端展示的短字符串。

参数:
  - result (ConnectivityResult): 单条探测结果。

返回:
  - string: “连通”或“失败”以及对应的延迟或错误摘要。
*/
func FormatConnectivity(result ConnectivityResult) string {
	if result.OK {
		return fmt.Sprintf("连通 · %s", result.Latency.Round(time.Millisecond))
	}
	return fmt.Sprintf("失败 · %s", result.Error)
}
