package test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ctkqiang/nezha_cli/internal/wireless/esp"
)

/*
TestESPEncodeCommand 验证主机命令帧头、命令字与小端长度。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestESPEncodeCommand(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	frame := esp.EncodeCommand(esp.CmdInject, payload)

	if len(frame) != 4+len(payload) {
		t.Fatalf("命令帧长度错误: %d", len(frame))
	}
	if frame[0] != esp.FrameHeadHost || frame[1] != esp.CmdInject {
		t.Fatalf("帧头或命令字错误: %x", frame[:2])
	}
	if frame[2] != 3 || frame[3] != 0 {
		t.Fatalf("小端长度错误: %x", frame[2:4])
	}
	if !bytes.Equal(frame[4:], payload) {
		t.Fatalf("载荷错误: %x", frame[4:])
	}

	large := esp.EncodeCommand(esp.CmdScan, make([]byte, 300))
	if large[2] != 44 || large[3] != 1 {
		t.Fatalf("跨字节长度编码错误: %x", large[2:4])
	}
}

/*
TestESPDecodeReply 验证回复帧解析、跨包累积与杂散字节重同步。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestESPDecodeReply(t *testing.T) {
	stream := append([]byte("boot log\r\n"), 0x5A, esp.RepScanEntry, 0x02, 0x00, 0xAA, 0xBB)

	command, payload, rest, ok := esp.DecodeReply(stream)
	if !ok {
		t.Fatal("应成功解析回复帧")
	}
	if command != esp.RepScanEntry || !bytes.Equal(payload, []byte{0xAA, 0xBB}) {
		t.Fatalf("解析结果错误: 0x%02X %x", command, payload)
	}
	if len(rest) != 0 {
		t.Fatalf("剩余字节错误: %x", rest)
	}
}

/*
TestESPDecodeReplyPartial 验证不足一帧时返回 ok=false 并保留已收字节。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestESPDecodeReplyPartial(t *testing.T) {
	partial := []byte{0x5A, esp.RepPong, 0x02, 0x00, 0x01}
	command, payload, rest, ok := esp.DecodeReply(partial)
	if ok {
		t.Fatal("不完整帧不应解析成功")
	}
	if command != 0 || payload != nil {
		t.Fatalf("不完整帧不应返回内容: %d %x", command, payload)
	}
	if !bytes.Equal(rest, partial) {
		t.Fatalf("不完整帧应保留原始字节: %x", rest)
	}

	if _, _, rest, ok := esp.DecodeReply([]byte{0x00, 0x01}); ok || len(rest) != 0 {
		t.Fatalf("无帧头字节应被丢弃: %x", rest)
	}
}

/*
TestESPDecodeReplySequential 验证一次读入多帧时按顺序拆包。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestESPDecodeReplySequential(t *testing.T) {
	first := esp.EncodeCommand(esp.RepPong, []byte{0x01})
	second := esp.EncodeCommand(esp.RepScanDone, nil)
	stream := append([]byte{0x5A}, first[1:]...)
	stream = append(stream, append([]byte{0x5A}, second[1:]...)...)

	command, payload, rest, ok := esp.DecodeReply(stream)
	if !ok || command != esp.RepPong || !bytes.Equal(payload, []byte{0x01}) {
		t.Fatalf("第一帧解析错误: 0x%02X %x", command, payload)
	}

	command, payload, rest, ok = esp.DecodeReply(rest)
	if !ok || command != esp.RepScanDone || len(payload) != 0 || len(rest) != 0 {
		t.Fatalf("第二帧解析错误: 0x%02X %x", command, payload)
	}
}

/*
TestESPParseScanEntry 验证 BSSID、信道、有符号 RSSI 与 SSID 解析。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestESPParseScanEntry(t *testing.T) {
	payload := []byte{
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x06,
		0xD8,
		0x08,
		'N', 'e', 'z', 'h', 'a', 'L', 'a', 'b',
	}

	network, err := esp.ParseScanEntry(payload)
	if err != nil {
		t.Fatalf("解析扫描条目失败: %v", err)
	}
	if network.BSSID != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("BSSID 错误: %s", network.BSSID)
	}
	if network.Channel != 6 {
		t.Fatalf("信道错误: %d", network.Channel)
	}
	if network.RSSI != -40 {
		t.Fatalf("RSSI 应有符号解析: %d", network.RSSI)
	}
	if network.SSID != "NezhaLab" {
		t.Fatalf("SSID 错误: %q", network.SSID)
	}

	if _, err := esp.ParseScanEntry(make([]byte, 8)); err == nil {
		t.Fatal("过短条目应返回错误")
	}
	if _, err := esp.ParseScanEntry([]byte{0, 0, 0, 0, 0, 0, 1, 1, 32, 'a'}); err == nil {
		t.Fatal("SSID 越界应返回错误")
	}
}

/*
TestESPParsePong 验证握手应答的新旧固件兼容。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestESPParsePong(t *testing.T) {
	pong, err := esp.ParsePong([]byte{esp.ProtoVersion, esp.CapBand5GHz})
	if err != nil {
		t.Fatalf("解析 PONG 失败: %v", err)
	}
	if pong.Version != esp.ProtoVersion || pong.Caps != esp.CapBand5GHz {
		t.Fatalf("PONG 内容错误: %+v", pong)
	}

	old, err := esp.ParsePong([]byte{esp.ProtoVersion})
	if err != nil {
		t.Fatalf("旧固件 PONG 解析失败: %v", err)
	}
	if old.Caps != 0 {
		t.Fatalf("旧固件能力位图应为 0: %d", old.Caps)
	}

	if _, err := esp.ParsePong(nil); err == nil {
		t.Fatal("空 PONG 应返回错误")
	}
}

/*
TestESPParseClone 验证克隆结果与在线设备列表解析。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestESPParseClone(t *testing.T) {
	result, err := esp.ParseCloneResult([]byte{1, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	if err != nil {
		t.Fatalf("解析克隆结果失败: %v", err)
	}
	if !result.OK || result.APMAC != "02:00:00:00:00:01" {
		t.Fatalf("克隆结果错误: %+v", result)
	}

	failed, err := esp.ParseCloneResult([]byte{0, 0, 0, 0, 0, 0, 0})
	if err != nil || failed.OK {
		t.Fatalf("失败结果解析错误: %+v %v", failed, err)
	}
	if _, err := esp.ParseCloneResult([]byte{1, 2}); err == nil {
		t.Fatal("短克隆结果应返回错误")
	}

	status, err := esp.ParseCloneStatus([]byte{2, 1, 2, 3, 4, 5, 6, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})
	if err != nil {
		t.Fatalf("解析克隆状态失败: %v", err)
	}
	if len(status) != 2 || status[0] != "01:02:03:04:05:06" || status[1] != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("状态列表错误: %v", status)
	}

	if _, err := esp.ParseCloneStatus(nil); err == nil {
		t.Fatal("空状态应返回错误")
	}
	if _, err := esp.ParseCloneStatus([]byte{3, 1, 2, 3}); err == nil {
		t.Fatal("MAC 列表越界应返回错误")
	}
}

/*
TestESPFormatMAC 验证 MAC 格式化与短输入。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestESPFormatMAC(t *testing.T) {
	if got := esp.FormatMAC([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}); got != "00:11:22:33:44:55" {
		t.Fatalf("MAC 格式化错误: %s", got)
	}
	if got := esp.FormatMAC([]byte{1, 2}); got != "" {
		t.Fatalf("短 MAC 应返回空串: %q", got)
	}
}

/*
TestESPValidateSSIDAndPassword 验证协议长度约束。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestESPValidateSSIDAndPassword(t *testing.T) {
	if err := esp.ValidateSSID("NezhaLab"); err != nil {
		t.Fatalf("合法 SSID 被拒绝: %v", err)
	}
	if err := esp.ValidateSSID(""); err == nil {
		t.Fatal("空 SSID 应返回错误")
	}
	if err := esp.ValidateSSID(strings.Repeat("a", 33)); err == nil {
		t.Fatal("33 字节 SSID 应返回错误")
	}
	if err := esp.ValidateSSID(strings.Repeat("中", 10)); err != nil {
		t.Fatalf("30 字节 CJK SSID 应被接受: %v", err)
	}
	if err := esp.ValidateSSID(strings.Repeat("中", 10) + "ab"); err != nil {
		t.Fatalf("32 字节 CJK SSID 应被接受: %v", err)
	}
	if err := esp.ValidateSSID(strings.Repeat("中", 11)); err == nil {
		t.Fatal("33 字节 CJK SSID 应被拒绝")
	}

	if err := esp.ValidatePassword(""); err != nil {
		t.Fatalf("开放网络空密码应被接受: %v", err)
	}
	if err := esp.ValidatePassword(strings.Repeat("a", 63)); err != nil {
		t.Fatalf("63 字节密码应被接受: %v", err)
	}
	if err := esp.ValidatePassword(strings.Repeat("a", 64)); err == nil {
		t.Fatal("64 字节密码应被拒绝")
	}
}

/*
TestESPConstants 验证协议常量与固件约定一致。
这些取值直接对应 wifisec 固件的字节协议，不允许随意调整。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestESPConstants(t *testing.T) {
	if esp.FrameHeadHost != 0xA5 || esp.FrameHeadESP != 0x5A {
		t.Fatalf("帧头魔数错误: 0x%02X 0x%02X", esp.FrameHeadHost, esp.FrameHeadESP)
	}
	if esp.CmdPing != 0x00 || esp.CmdScan != 0x01 || esp.CmdInject != 0x02 ||
		esp.CmdAssoc != 0x03 || esp.CmdClone != 0x05 || esp.CmdCloneStatus != 0x06 {
		t.Fatal("主机命令字与固件协议不一致")
	}
	if esp.RepPong != 0x00 || esp.RepScanEntry != 0x01 || esp.RepScanDone != 0x02 ||
		esp.RepAssocResult != 0x03 || esp.RepError != 0x04 ||
		esp.RepCloneResult != 0x05 || esp.RepCloneStatus != 0x06 {
		t.Fatal("固件回复字与协议不一致")
	}
	if esp.ProtoVersion != 1 || esp.BaudRate != 115200 || esp.CapBand5GHz != 0x01 {
		t.Fatal("协议版本、波特率或能力位定义错误")
	}
}
