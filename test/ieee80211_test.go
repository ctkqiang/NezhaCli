package test

import (
	"bytes"
	"net"
	"testing"

	"github.com/ctkqiang/nezha_cli/internal/wireless/ieee80211"
)

/*
TestBuildDeauthFrame 验证 34 字节 deauth 帧的 radiotap、MAC 头与 Reason Code。
帧布局必须与 ESP 固件期望的注入格式一致。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestBuildDeauthFrame(t *testing.T) {
	bssid, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	frame, err := ieee80211.BuildDeauthFrame(bssid)
	if err != nil {
		t.Fatalf("构造 deauth 帧失败: %v", err)
	}

	if len(frame) != 34 || ieee80211.DeauthFrameLen != 34 {
		t.Fatalf("帧长度错误: %d", len(frame))
	}
	if got := int(frame[2]) | int(frame[3])<<8; got != ieee80211.RadiotapHeaderLen {
		t.Fatalf("radiotap 长度错误: %d", got)
	}
	if frame[0] != 0 {
		t.Fatalf("radiotap 版本应为 0: %d", frame[0])
	}
	if frame[8] != 0xC0 {
		t.Fatalf("Frame Control 应为 deauth(0xC0): 0x%02X", frame[8])
	}

	broadcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if !bytes.Equal(frame[12:18], broadcast) {
		t.Fatalf("addr1 应为广播地址: %x", frame[12:18])
	}
	if !bytes.Equal(frame[18:24], bssid) {
		t.Fatalf("addr2 应为 BSSID: %x", frame[18:24])
	}
	if !bytes.Equal(frame[24:30], bssid) {
		t.Fatalf("addr3 应为 BSSID: %x", frame[24:30])
	}
	if reason := uint16(frame[32]) | uint16(frame[33])<<8; reason != 7 {
		t.Fatalf("Reason Code 应为 7: %d", reason)
	}
}

/*
TestBuildDisassocFrame 验证 disassoc 子类型与定向接收方地址。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestBuildDisassocFrame(t *testing.T) {
	bssid, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	frame, err := ieee80211.BuildDisassocFrame(bssid)
	if err != nil {
		t.Fatalf("构造 disassoc 帧失败: %v", err)
	}
	if frame[8] != 0xA0 {
		t.Fatalf("Frame Control 应为 disassoc(0xA0): 0x%02X", frame[8])
	}

	station, _ := net.ParseMAC("11:22:33:44:55:66")
	directed, err := ieee80211.BuildManagementFrame(bssid, station, ieee80211.SubtypeDeauth, 3)
	if err != nil {
		t.Fatalf("构造定向帧失败: %v", err)
	}
	if !bytes.Equal(directed[12:18], station) {
		t.Fatalf("addr1 应为定向客户端: %x", directed[12:18])
	}
	if reason := uint16(directed[32]) | uint16(directed[33])<<8; reason != 3 {
		t.Fatalf("Reason Code 错误: %d", reason)
	}
}

/*
TestBuildManagementFrameValidation 验证 MAC 长度与子类型校验。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestBuildManagementFrameValidation(t *testing.T) {
	valid, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	broadcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	if _, err := ieee80211.BuildManagementFrame(net.HardwareAddr{1, 2, 3}, broadcast, ieee80211.SubtypeDeauth, 7); err == nil {
		t.Fatal("短 BSSID 应返回错误")
	}
	if _, err := ieee80211.BuildManagementFrame(valid, net.HardwareAddr{1, 2, 3}, ieee80211.SubtypeDeauth, 7); err == nil {
		t.Fatal("短接收方 MAC 应返回错误")
	}
	if _, err := ieee80211.BuildManagementFrame(valid, broadcast, 99, 7); err == nil {
		t.Fatal("非法子类型应返回错误")
	}
}

/*
TestRadioTapLen 验证 radiotap 头长度解析与边界检查。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestRadioTapLen(t *testing.T) {
	frame := make([]byte, 16)
	frame[2] = 8
	if length, ok := ieee80211.RadioTapLen(frame); !ok || length != 8 {
		t.Fatalf("radiotap 长度解析错误: %d %t", length, ok)
	}

	if _, ok := ieee80211.RadioTapLen([]byte{1, 2, 3}); ok {
		t.Fatal("过短帧不应解析成功")
	}

	invalid := make([]byte, 8)
	invalid[2] = 32
	if _, ok := ieee80211.RadioTapLen(invalid); ok {
		t.Fatal("超出帧长的 radiotap 头应被拒绝")
	}
}

/*
TestParseBeacon 验证信标帧 SSID 提取与地址字段解析。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestParseBeacon(t *testing.T) {
	frame := make([]byte, 24)
	frame[0] = byte(ieee80211.SubtypeBeacon << 4)
	copy(frame[4:10], net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[10:16], net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	copy(frame[16:22], net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})

	frame = append(frame, make([]byte, 12)...)
	ssid := []byte("NezhaLab")
	frame = append(frame, 0x00, byte(len(ssid)))
	frame = append(frame, ssid...)

	info, err := ieee80211.ParseManagement(frame)
	if err != nil {
		t.Fatalf("解析信标失败: %v", err)
	}
	if info.Subtype != ieee80211.SubtypeBeacon {
		t.Fatalf("子类型错误: %d", info.Subtype)
	}
	if info.SSID != "NezhaLab" {
		t.Fatalf("SSID 解析错误: %q", info.SSID)
	}
	if info.BSSID.String() != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("BSSID 解析错误: %s", info.BSSID)
	}
	if info.Transmitter.String() != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("发送方解析错误: %s", info.Transmitter)
	}
}

/*
TestParseManagementEdges 验证 deauth Reason Code、非管理帧与畸形帧。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestParseManagementEdges(t *testing.T) {
	reason := []byte{0x07, 0x00}
	frame := make([]byte, 24)
	frame[0] = byte(ieee80211.SubtypeDeauth << 4)
	frame = append(frame, reason...)

	info, err := ieee80211.ParseManagement(frame)
	if err != nil {
		t.Fatalf("解析 deauth 失败: %v", err)
	}
	if info.ReasonCode != 7 {
		t.Fatalf("Reason Code 错误: %d", info.ReasonCode)
	}

	data := make([]byte, 24)
	data[0] = 0x08
	if _, err := ieee80211.ParseManagement(data); err == nil {
		t.Fatal("数据帧应返回错误")
	}

	if _, err := ieee80211.ParseManagement([]byte{0x80}); err == nil {
		t.Fatal("过短帧应返回错误")
	}
}

/*
TestParseSSIDHidden 验证隐藏 SSID 返回空串，信息元素长度越界不会崩溃。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestParseSSIDHidden(t *testing.T) {
	frame := make([]byte, 24)
	frame[0] = byte(ieee80211.SubtypeBeacon << 4)
	frame = append(frame, make([]byte, 12)...)
	frame = append(frame, 0x00, 0x00)

	info, err := ieee80211.ParseManagement(frame)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if info.SSID != "" {
		t.Fatalf("隐藏 SSID 应为空: %q", info.SSID)
	}

	malformed := make([]byte, 24)
	malformed[0] = byte(ieee80211.SubtypeProbeResp << 4)
	malformed = append(malformed, make([]byte, 12)...)
	malformed = append(malformed, 0x00, 0x20, 'a')

	if info, err := ieee80211.ParseManagement(malformed); err != nil || info.SSID != "" {
		t.Fatalf("越界 SSID 元素应返回空串: %q %v", info.SSID, err)
	}
}
