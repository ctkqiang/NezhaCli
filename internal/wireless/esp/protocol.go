// esp 包实现 ESP8266/ESP32 协处理器串口协议与 802.11 帧注入控制。
//
// 宿主机只把开发板当作普通串口设备，射频完全由板载芯片执行，
// 因此该路径在无 Root 的 Termux/Android 上仍然可用。
//
// 与固件之间的协议为定长头小端帧：
//
//	主机→ESP: [0xA5][cmd][len_lo][len_hi][payload]
//	ESP→主机: [0x5A][cmd][len_lo][len_hi][payload]
package esp

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// FrameHeadHost 是主机发往固件的帧头魔数。
	FrameHeadHost = 0xA5

	// FrameHeadESP 是固件发往主机的帧头魔数。
	FrameHeadESP = 0x5A

	// CmdPing 触发 PONG 握手，载荷携带协议版本与能力位图。
	CmdPing = 0x00

	// CmdScan 请求扫描周边接入点。
	CmdScan = 0x01

	// CmdInject 注入 802.11 帧；载荷 = 信道(1) + 帧（不含 radiotap）。
	CmdInject = 0x02

	// CmdAssoc 尝试关联 AP；载荷 = ssidLen(1) + ssid + passLen(1) + password。
	CmdAssoc = 0x03

	// CmdClone 控制克隆 AP；载荷 = op(1) + channel(1) + ssidLen(1) + ssid + passLen(1) + password。
	CmdClone = 0x05

	// CmdCloneStatus 查询克隆 AP 的在线设备。
	CmdCloneStatus = 0x06

	// RepPong 是握手应答；载荷 = 协议版本(1) + 能力位图(1，旧固件可缺省)。
	RepPong = 0x00

	// RepScanEntry 是一条扫描结果。
	RepScanEntry = 0x01

	// RepScanDone 表示扫描结束。
	RepScanDone = 0x02

	// RepAssocResult 是关联结果；载荷 = result(1)，0 失败 1 成功。
	RepAssocResult = 0x03

	// RepError 是错误回复；载荷 = 出错命令(1) + 错误码(1)。
	RepError = 0x04

	// RepCloneResult 是克隆开关结果；载荷 = result(1) + apMAC(6)。
	RepCloneResult = 0x05

	// RepCloneStatus 是克隆状态；载荷 = count(1) + count×MAC(6)。
	RepCloneStatus = 0x06
)

const (
	// CloneOpDown 关闭克隆 AP。
	CloneOpDown = 0x00

	// CloneOpUp 开启克隆 AP。
	CloneOpUp = 0x01

	// ProtoVersion 是本程序支持的固件协议版本。
	ProtoVersion = 1

	// CapBand5GHz 是能力位图 bit0：固件具备 5GHz 注入能力。
	CapBand5GHz byte = 0x01
)

const (
	// FrameRetryTimeout 是单帧回复的读取预算，覆盖一次完整扫描。
	FrameRetryTimeout = 15 * time.Second

	// CloneReplyTimeout 覆盖克隆开关与状态查询的回复预算。
	CloneReplyTimeout = 5 * time.Second

	// HandshakeAttempts 是冷启动阶段的握手重试次数。
	HandshakeAttempts = 15

	// HandshakeTimeout 是单次握手的等待预算。
	HandshakeTimeout = 500 * time.Millisecond

	// BaudRate 与固件 Serial.begin 保持一致。
	BaudRate = 115200
)

var (
	// ErrReplyTimeout 表示在预算内没有收到完整回复帧。
	ErrReplyTimeout = errors.New("读取回复帧超时")

	// ErrFirmwareVersion 表示固件协议版本不匹配。
	ErrFirmwareVersion = errors.New("固件协议版本不兼容")
)

// Network 是一个由 ESP 协处理器扫描到的接入点。
type Network struct {
	SSID    string
	BSSID   string
	Channel int
	RSSI    int
}

// Pong 是固件握手回复中的协议版本与能力位图。
type Pong struct {
	Version byte
	Caps    byte
}

// CloneResult 是克隆 AP 开关的回复。
type CloneResult struct {
	OK    bool
	APMAC string
}

/*
EncodeCommand 按协议打包主机→固件命令帧。

参数:
  - cmd (byte): 命令字。
  - payload ([]byte): 命令载荷。

返回:
  - []byte: 完整命令帧。
*/
func EncodeCommand(cmd byte, payload []byte) []byte {
	frame := make([]byte, 0, 4+len(payload))
	frame = append(frame, FrameHeadHost, cmd, byte(len(payload)), byte(len(payload)>>8))
	return append(frame, payload...)
}

/*
DecodeReply 从字节流中拆出一帧固件回复；流不足一帧时返回 ok=false。
帧头之前的杂散字节会被丢弃后重新同步，以跳过芯片上电时的启动日志。

参数:
  - stream ([]byte): 累积的串口字节流。

返回:
  - byte: 回复命令字。
  - []byte: 回复载荷。
  - []byte: 剩余未消费字节。
  - bool: 是否成功拆出一帧。
*/
func DecodeReply(stream []byte) (byte, []byte, []byte, bool) {
	for len(stream) > 0 && stream[0] != FrameHeadESP {
		stream = stream[1:]
	}

	if len(stream) < 4 {
		return 0, nil, stream, false
	}

	frameLen := 4 + int(stream[2]) + int(stream[3])<<8
	if frameLen < 4 || len(stream) < frameLen {
		return 0, nil, stream, false
	}

	return stream[1], stream[4:frameLen], stream[frameLen:], true
}

/*
ParseScanEntry 解析一条扫描条目载荷：
bssid(6) + channel(1) + rssi(1，有符号) + ssidLen(1) + ssid。

参数:
  - payload ([]byte): 扫描条目载荷。

返回:
  - Network: 接入点信息。
  - error: 载荷长度不足或 SSID 越界时返回错误。
*/
func ParseScanEntry(payload []byte) (Network, error) {
	if len(payload) < 9 {
		return Network{}, errors.New("扫描条目长度不足 9 字节")
	}

	ssidLen := int(payload[8])
	if len(payload) < 9+ssidLen {
		return Network{}, errors.New("扫描条目 SSID 长度越界")
	}

	return Network{
		BSSID:   FormatMAC(payload[0:6]),
		Channel: int(payload[6]),
		RSSI:    int(int8(payload[7])),
		SSID:    string(payload[9 : 9+ssidLen]),
	}, nil
}

/*
ParsePong 解析握手应答载荷。旧固件只回版本号一个字节，此时能力位图按 0 处理。

参数:
  - payload ([]byte): PONG 载荷。

返回:
  - Pong: 协议版本与能力位图。
  - error: 载荷为空时返回错误。
*/
func ParsePong(payload []byte) (Pong, error) {
	if len(payload) < 1 {
		return Pong{}, errors.New("PONG 载荷为空，固件未上报协议版本")
	}

	pong := Pong{Version: payload[0]}
	if len(payload) >= 2 {
		pong.Caps = payload[1]
	}
	return pong, nil
}

/*
ParseCloneResult 解析克隆结果载荷：result(1) + apMAC(6)。

参数:
  - payload ([]byte): 克隆结果载荷。

返回:
  - CloneResult: 是否成功与克隆 AP 的 MAC。
  - error: 载荷长度不足时返回错误。
*/
func ParseCloneResult(payload []byte) (CloneResult, error) {
	if len(payload) < 7 {
		return CloneResult{}, errors.New("克隆结果载荷长度不足 7 字节")
	}
	return CloneResult{OK: payload[0] == 1, APMAC: FormatMAC(payload[1:7])}, nil
}

/*
ParseCloneStatus 解析克隆状态载荷：count(1) + count×MAC(6)。

参数:
  - payload ([]byte): 克隆状态载荷。

返回:
  - []string: 在线设备 MAC 列表。
  - error: 载荷为空或 MAC 列表越界时返回错误。
*/
func ParseCloneStatus(payload []byte) ([]string, error) {
	if len(payload) < 1 {
		return nil, errors.New("克隆状态载荷为空")
	}

	count := int(payload[0])
	if len(payload) < 1+6*count {
		return nil, errors.New("克隆状态 MAC 列表越界")
	}

	macs := make([]string, 0, count)
	for index := 0; index < count; index++ {
		offset := 1 + index*6
		macs = append(macs, FormatMAC(payload[offset:offset+6]))
	}
	return macs, nil
}

/*
FormatMAC 把 6 字节 MAC 格式化为小写冒号分隔串。

参数:
  - address ([]byte): 至少 6 字节的 MAC。

返回:
  - string: 格式化后的 MAC；长度不足时返回空串。
*/
func FormatMAC(address []byte) string {
	if len(address) < 6 {
		return ""
	}
	parts := make([]string, 6)
	for index := 0; index < 6; index++ {
		parts[index] = fmt.Sprintf("%02x", address[index])
	}
	return strings.Join(parts, ":")
}

/*
ValidateSSID 校验 SSID 长度，协议上限为 32 字节。

参数:
  - ssid (string): 待校验 SSID。

返回:
  - error: 长度超出 1-32 字节时返回错误。
*/
func ValidateSSID(ssid string) error {
	length := len([]byte(ssid))
	if length < 1 || length > 32 {
		return errors.New("SSID 长度需在 1-32 字节之间")
	}
	return nil
}

/*
ValidatePassword 校验无线密码长度，协议上限为 63 字节。
空密码表示开放网络，允许通过。

参数:
  - password (string): 待校验密码。

返回:
  - error: 长度超过 63 字节时返回错误。
*/
func ValidatePassword(password string) error {
	if len([]byte(password)) > 63 {
		return errors.New("密码长度超过 63 字节上限")
	}
	return nil
}

/*
buildClonePayload 打包克隆命令载荷：op(1) + channel(1) + ssidLen(1) + ssid
+ passLen(1) + password。down 指令以信道 1、空 SSID 占位。

参数:
  - op (byte): CloneOpUp 或 CloneOpDown。
  - channel (int): 克隆 AP 信道。
  - ssid (string): 克隆 SSID。
  - password (string): 克隆密码。

返回:
  - []byte: 克隆命令载荷。
  - error: SSID 或密码长度非法时返回错误。
*/
func buildClonePayload(op byte, channel int, ssid string, password string) ([]byte, error) {
	if channel < 1 || channel > 196 {
		return nil, fmt.Errorf("信道超出范围: %d", channel)
	}
	if op == CloneOpUp {
		if err := ValidateSSID(ssid); err != nil {
			return nil, err
		}
	}
	if err := ValidatePassword(password); err != nil {
		return nil, err
	}

	ssidBytes := []byte(ssid)
	passwordBytes := []byte(password)
	payload := make([]byte, 0, 4+len(ssidBytes)+len(passwordBytes))
	payload = append(payload, op, byte(channel), byte(len(ssidBytes)))
	payload = append(payload, ssidBytes...)
	payload = append(payload, byte(len(passwordBytes)))
	payload = append(payload, passwordBytes...)
	return payload, nil
}

/*
cloneFirmwareError 把错误回复翻译为可操作的中文提示。
错误码 255 表示固件没有实现该命令，通常意味着固件版本过旧。

参数:
  - operation (string): 操作名称。
  - reply ([]byte): 错误回复载荷。

返回:
  - error: 面向操作员的错误。
*/
func cloneFirmwareError(operation string, reply []byte) error {
	if len(reply) >= 2 && reply[1] == 0xFF {
		return fmt.Errorf("固件不支持%s命令（错误码 255），请重新烧录最新固件", operation)
	}
	if len(reply) >= 2 {
		return fmt.Errorf("固件执行%s命令失败，错误码 %d", operation, reply[1])
	}
	return fmt.Errorf("固件执行%s命令失败", operation)
}

/*
firmwareError 把任意命令的错误回复翻译为中文错误。

参数:
  - reply ([]byte): 错误回复载荷。

返回:
  - error: 面向操作员的错误。
*/
func firmwareError(reply []byte) error {
	if len(reply) >= 2 {
		return fmt.Errorf("固件执行命令 0x%02X 失败，错误码 %d", reply[0], reply[1])
	}
	return errors.New("固件返回错误，但未携带错误码")
}
