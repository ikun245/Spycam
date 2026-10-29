package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

// SuricataCmd 通过 unix socket 向常驻引擎发送控制命令（协议：JSON 行 + 响应 JSON 行）。
// 参考 suricatasc：先发 {"version":"0.3"} 握手，再发 {"command":...}。
type SuricataCmd struct {
	socketPath string
	timeout    time.Duration
}

// NewSuricataCmd 构造命令客户端。
func NewSuricataCmd(socketPath string, timeout time.Duration) *SuricataCmd {
	return &SuricataCmd{socketPath: socketPath, timeout: timeout}
}

type suricataResponse struct {
	Return  string          `json:"return"`
	Message json.RawMessage `json:"message"`
}

// Do 连接 socket，握手后发送单条命令并返回响应 message（原始 JSON）。
func (c *SuricataCmd) Do(ctx context.Context, command string, arguments any) (json.RawMessage, error) {
	d := net.Dialer{Timeout: c.timeout}
	conn, err := d.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		return nil, fmt.Errorf("dial suricata socket: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.timeout))

	// 握手：官方 suricatasc 发送 {"version":"0.2"}，无换行结尾
	if err := writeMsg(conn, map[string]string{"version": "0.2"}); err != nil {
		return nil, fmt.Errorf("handshake write: %w", err)
	}
	if _, err := readResponse(conn); err != nil {
		return nil, fmt.Errorf("handshake read: %w", err)
	}

	req := map[string]any{"command": command}
	if arguments != nil {
		req["arguments"] = arguments
	}
	// 官方客户端命令消息以 \n 结尾（json.dumps(cmdmsg)+"\n"）
	if err := writeLine(conn, req); err != nil {
		return nil, fmt.Errorf("command write: %w", err)
	}
	resp, err := readResponse(conn)
	if err != nil {
		return nil, fmt.Errorf("command read: %w", err)
	}
	if resp.Return != "OK" && resp.Return != "Success" {
		msg := strings.TrimSpace(string(resp.Message))
		return resp.Message, fmt.Errorf("suricata %s: %s", command, msg)
	}
	return resp.Message, nil
}

func writeMsg(conn net.Conn, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = conn.Write(data)
	return err
}

func writeLine(conn net.Conn, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = conn.Write(append(data, '\n'))
	return err
}

func readResponse(conn net.Conn) (*suricataResponse, error) {
	dec := json.NewDecoder(conn)
	var resp suricataResponse
	if err := dec.Decode(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
