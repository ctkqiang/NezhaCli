package esp

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/wireless/ieee80211"
)

// Injector 封装串口句柄，串口是严格请求-应答流，事务级互斥保证并发调用不交错。
type Injector struct {
	mutex      sync.Mutex
	port       serialPort
	portName   string
	channel    int
	pong       Pong
	rx         []byte
	observedRx bool
}

/*
Open 打开指定串口并完成固件握手后返回。
portName 为空时自动选择唯一的 USB 串口设备。

参数:
  - portName (string): 串口设备路径；为空表示自动探测。

返回:
  - *Injector: 已完成握手的协处理器控制句柄。
  - error: 打开串口、复位开发板或握手失败时返回错误。
*/
func Open(portName string) (*Injector, error) {
	if portName == "" {
		detected, err := DefaultPort()
		if err != nil {
			return nil, err
		}
		portName = detected
	}

	port, err := openSerialPort(portName)
	if err != nil {
		return nil, fmt.Errorf("打开串口 %s 失败: %w", portName, err)
	}

	if err := resetIntoRun(port); err != nil {
		_ = port.Close()
		return nil, fmt.Errorf("复位开发板失败: %w", err)
	}

	injector := &Injector{port: port, portName: portName, channel: 1}
	if err := injector.handshake(); err != nil {
		_ = port.Close()
		return nil, err
	}
	return injector, nil
}

/*
resetIntoRun 通过 DTR/RTS 时序让 ESP 从 Flash 正常启动。
自动复位电路把 DTR 接到 GPIO0、RTS 接到 EN；先保证 GPIO0 为高，
再拉低 EN 保持 100 毫秒，最后释放 EN，芯片即从 Flash 启动。

参数:
  - port (serialPort): 已打开的串口。

返回:
  - error: 任一步骤失败时返回错误。
*/
func resetIntoRun(port serialPort) error {
	if err := port.SetDTR(false); err != nil {
		return err
	}
	if err := port.SetRTS(true); err != nil {
		return err
	}

	time.Sleep(100 * time.Millisecond)

	return port.SetRTS(false)
}

/*
handshake 通过 PING/PONG 确认固件就绪，并记录协议版本与能力位图。
打开串口会触发板子复位，boot 期间发出的命令全部丢失，因此需要重试。

参数:
  - 无。

返回:
  - error: 固件未响应、协议版本不兼容或串口写入失败时返回错误。
*/
func (i *Injector) handshake() error {
	_ = i.port.FlushInput()

	for attempt := 0; attempt < HandshakeAttempts; attempt++ {
		if _, err := i.port.Write(EncodeCommand(CmdPing, nil)); err != nil {
			return fmt.Errorf("发送握手命令失败: %w", err)
		}

		command, payload, err := i.readFrame(HandshakeTimeout)
		if err != nil || command != RepPong {
			continue
		}

		pong, err := ParsePong(payload)
		if err != nil {
			continue
		}
		if pong.Version != ProtoVersion {
			return fmt.Errorf("%w: 固件 v%d，本程序支持 v%d；请重新烧录最新固件",
				ErrFirmwareVersion, pong.Version, ProtoVersion)
		}

		i.pong = pong
		return nil
	}

	if i.observedRx {
		return errors.New("固件握手失败：串口有数据但不是有效 PONG；固件可能未烧录或版本过旧")
	}
	return errors.New("固件握手失败：串口完全无数据；请检查供电、数据线与端口选择，并确认固件正在运行")
}

/*
readFrame 在整体预算内读取一帧完整回复。
串口读取使用滚动截止时间，避免单次读超时导致整体无限等待。

参数:
  - timeout (time.Duration): 本帧的整体读取预算。

返回:
  - byte: 回复命令字。
  - []byte: 回复载荷。
  - error: 超时或串口读取失败时返回错误。
*/
func (i *Injector) readFrame(timeout time.Duration) (byte, []byte, error) {
	deadline := time.Now().Add(timeout)
	chunk := make([]byte, 128)

	for {
		if command, payload, rest, ok := DecodeReply(i.rx); ok {
			i.rx = rest
			return command, payload, nil
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, nil, ErrReplyTimeout
		}
		if err := i.port.SetReadDeadline(time.Now().Add(remaining)); err != nil {
			return 0, nil, fmt.Errorf("设置串口读超时失败: %w", err)
		}

		read, err := i.port.Read(chunk)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return 0, nil, ErrReplyTimeout
			}
			return 0, nil, err
		}
		if read == 0 {
			return 0, nil, ErrReplyTimeout
		}

		i.observedRx = true
		i.rx = append(i.rx, chunk[:read]...)
	}
}

/*
FirmwareVersion 返回握手时固件上报的协议版本。

参数:
  - 无。

返回:
  - byte: 协议版本。
*/
func (i *Injector) FirmwareVersion() byte {
	return i.pong.Version
}

/*
Supports5GHz 报告固件是否声明了 5GHz 注入能力。

参数:
  - 无。

返回:
  - bool: 能力位图 bit0 为 1 时返回 true。
*/
func (i *Injector) Supports5GHz() bool {
	return i.pong.Caps&CapBand5GHz != 0
}

/*
PortName 返回当前打开的设备路径，供日志与错误提示使用。

参数:
  - 无。

返回:
  - string: 串口设备路径。
*/
func (i *Injector) PortName() string {
	return i.portName
}

/*
SetChannel 缓存注入信道；实际切信道随每帧注入命令下发。

参数:
  - channel (int): 目标信道。

返回:
  - error: 信道超出 1-196 时返回错误。
*/
func (i *Injector) SetChannel(channel int) error {
	if channel < 1 || channel > 196 {
		return fmt.Errorf("信道超出范围: %d", channel)
	}

	i.mutex.Lock()
	defer i.mutex.Unlock()

	i.channel = channel
	return nil
}

/*
Inject 把一帧带 radiotap 头的 802.11 帧经串口交给固件注入。
固件的自由帧 API 只接受纯 802.11 帧，这里按 radiotap 长度剥掉头部。

参数:
  - frame ([]byte): 含 radiotap 头的完整帧。

返回:
  - error: 帧过短、信道未设置或串口写入失败时返回错误。
*/
func (i *Injector) Inject(frame []byte) error {
	if len(frame) <= ieee80211.RadiotapHeaderLen {
		return errors.New("帧长度不足，缺少 radiotap 头")
	}

	headerLength := ieee80211.RadiotapHeaderLen
	if length, ok := ieee80211.RadioTapLen(frame); ok {
		headerLength = length
	}

	i.mutex.Lock()
	channel := i.channel
	i.mutex.Unlock()

	return i.InjectRaw(channel, frame[headerLength:])
}

/*
InjectRaw 把不带 radiotap 头的 802.11 帧交给固件，并逐帧下发信道。

参数:
  - channel (int): 注入信道。
  - frame ([]byte): 纯 802.11 帧。

返回:
  - error: 帧为空、信道非法或串口写入失败时返回错误。
*/
func (i *Injector) InjectRaw(channel int, frame []byte) error {
	if len(frame) == 0 {
		return errors.New("注入帧不能为空")
	}
	if channel < 1 || channel > 196 {
		return fmt.Errorf("信道超出范围: %d", channel)
	}

	payload := make([]byte, 0, 1+len(frame))
	payload = append(payload, byte(channel))
	payload = append(payload, frame...)

	i.mutex.Lock()
	defer i.mutex.Unlock()

	if _, err := i.port.Write(EncodeCommand(CmdInject, payload)); err != nil {
		return fmt.Errorf("发送注入命令失败: %w", err)
	}
	return nil
}

/*
Scan 请求固件扫描周边网络，流式读取条目直到收到结束帧。

参数:
  - 无。

返回:
  - []Network: 扫描到的接入点列表。
  - error: 发送命令失败、扫描超时或固件报错时返回错误。
*/
func (i *Injector) Scan() ([]Network, error) {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	if _, err := i.port.Write(EncodeCommand(CmdScan, nil)); err != nil {
		return nil, fmt.Errorf("发送扫描命令失败: %w", err)
	}

	networks := make([]Network, 0, 16)
	for {
		command, payload, err := i.readFrame(FrameRetryTimeout)
		if err != nil {
			return nil, fmt.Errorf("扫描超时：固件已连接但未回传结果: %w", err)
		}

		switch command {
		case RepScanEntry:
			network, err := ParseScanEntry(payload)
			if err == nil {
				networks = append(networks, network)
			}
		case RepScanDone:
			return networks, nil
		case RepPong:
			continue
		case RepError:
			return nil, firmwareError(payload)
		default:
			return nil, fmt.Errorf("扫描收到意外回复帧 0x%02X", command)
		}
	}
}

/*
Associate 让固件尝试用给定 SSID 与密码关联 AP，并立即断开。
本方法用于在线密码字典爆破：每个密码尝试一次，命中即返回 true。

参数:
  - ssid (string): 目标 SSID。
  - password (string): 待尝试密码。

返回:
  - bool: 关联成功时返回 true。
  - error: 参数非法、发送失败或等待结果超时/固件报错时返回错误。
*/
func (i *Injector) Associate(ssid string, password string) (bool, error) {
	if err := ValidateSSID(ssid); err != nil {
		return false, err
	}
	if err := ValidatePassword(password); err != nil {
		return false, err
	}

	ssidBytes := []byte(ssid)
	passwordBytes := []byte(password)
	payload := make([]byte, 0, 2+len(ssidBytes)+len(passwordBytes))
	payload = append(payload, byte(len(ssidBytes)))
	payload = append(payload, ssidBytes...)
	payload = append(payload, byte(len(passwordBytes)))
	payload = append(payload, passwordBytes...)

	i.mutex.Lock()
	defer i.mutex.Unlock()

	if _, err := i.port.Write(EncodeCommand(CmdAssoc, payload)); err != nil {
		return false, fmt.Errorf("发送关联命令失败: %w", err)
	}

	command, reply, err := i.readFrame(FrameRetryTimeout)
	if err != nil {
		return false, fmt.Errorf("等待关联结果超时: %w", err)
	}

	switch command {
	case RepAssocResult:
		if len(reply) < 1 {
			return false, errors.New("关联结果帧载荷为空")
		}
		return reply[0] == 1, nil
	case RepError:
		return false, firmwareError(reply)
	default:
		return false, fmt.Errorf("关联命令收到意外回复帧 0x%02X", command)
	}
}

/*
CloneAPUp 让固件在指定信道开启同名同密码的克隆 AP，并返回克隆 AP 的 MAC。

参数:
  - ssid (string): 克隆 SSID。
  - password (string): 克隆密码；空串表示开放网络。
  - channel (int): 克隆 AP 信道。

返回:
  - string: 克隆 AP 自身 MAC。
  - error: 参数非法、固件拒绝或等待结果超时/报错时返回错误。
*/
func (i *Injector) CloneAPUp(ssid string, password string, channel int) (string, error) {
	payload, err := buildClonePayload(CloneOpUp, channel, ssid, password)
	if err != nil {
		return "", err
	}

	i.mutex.Lock()
	defer i.mutex.Unlock()

	if _, err := i.port.Write(EncodeCommand(CmdClone, payload)); err != nil {
		return "", fmt.Errorf("发送克隆命令失败: %w", err)
	}

	command, reply, err := i.readFrame(CloneReplyTimeout)
	if err != nil {
		return "", fmt.Errorf("等待克隆结果超时: %w", err)
	}

	switch command {
	case RepCloneResult:
		result, err := ParseCloneResult(reply)
		if err != nil {
			return "", err
		}
		if !result.OK {
			return "", errors.New("固件开启 SoftAP 失败（信道超出射频能力或参数非法）")
		}
		return result.APMAC, nil
	case RepError:
		return "", cloneFirmwareError("克隆", reply)
	default:
		return "", fmt.Errorf("克隆命令收到意外回复帧 0x%02X", command)
	}
}

/*
CloneAPDown 停止固件上的克隆 AP 并恢复 STA 模式。

参数:
  - 无。

返回:
  - error: 发送失败、固件拒绝或等待结果超时/报错时返回错误。
*/
func (i *Injector) CloneAPDown() error {
	payload, err := buildClonePayload(CloneOpDown, 1, "", "")
	if err != nil {
		return err
	}

	i.mutex.Lock()
	defer i.mutex.Unlock()

	if _, err := i.port.Write(EncodeCommand(CmdClone, payload)); err != nil {
		return fmt.Errorf("发送停止克隆命令失败: %w", err)
	}

	command, reply, err := i.readFrame(CloneReplyTimeout)
	if err != nil {
		return fmt.Errorf("等待停止克隆结果超时: %w", err)
	}

	switch command {
	case RepCloneResult:
		result, err := ParseCloneResult(reply)
		if err != nil {
			return err
		}
		if !result.OK {
			return errors.New("固件停止 SoftAP 失败")
		}
		return nil
	case RepError:
		return cloneFirmwareError("停止克隆", reply)
	default:
		return fmt.Errorf("停止克隆命令收到意外回复帧 0x%02X", command)
	}
}

/*
CloneStatus 查询克隆 AP 当前接入的设备 MAC 列表。

参数:
  - 无。

返回:
  - []string: 在线设备 MAC 列表。
  - error: 发送失败、固件拒绝或等待结果超时/报错时返回错误。
*/
func (i *Injector) CloneStatus() ([]string, error) {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	if _, err := i.port.Write(EncodeCommand(CmdCloneStatus, nil)); err != nil {
		return nil, fmt.Errorf("发送克隆状态查询失败: %w", err)
	}

	command, reply, err := i.readFrame(CloneReplyTimeout)
	if err != nil {
		return nil, fmt.Errorf("等待克隆状态超时: %w", err)
	}

	switch command {
	case RepCloneStatus:
		return ParseCloneStatus(reply)
	case RepError:
		return nil, cloneFirmwareError("克隆状态", reply)
	default:
		return nil, fmt.Errorf("克隆状态查询收到意外回复帧 0x%02X", command)
	}
}

/*
Close 关闭串口。重复调用是安全的。

参数:
  - 无。

返回:
  - error: 串口关闭失败时返回错误。
*/
func (i *Injector) Close() error {
	if i.port == nil {
		return nil
	}
	return i.port.Close()
}
