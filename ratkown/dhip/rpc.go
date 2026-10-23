package dhip

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"ratkown/ratkown/net"
)

func DHIPGetTable(dh *net.DHIPClient, name string, id int) ([]any, error) {
	r, err := dh.Call("configManager.getConfig", map[string]any{"name": name}, id, nil, nil)
	if err != nil {
		return nil, err
	}
	if ok, _ := r["result"].(bool); !ok {
		return nil, fmt.Errorf("getConfig %s: result false (%v)", name, r["error"])
	}
	params, _ := r["params"].(map[string]any)
	if params == nil {
		return nil, fmt.Errorf("getConfig %s: no params", name)
	}
	switch t := params["table"].(type) {
	case []any:
		return t, nil
	case map[string]any:
		return []any{t}, nil
	default:
		return nil, fmt.Errorf("getConfig %s: unexpected table shape", name)
	}
}

type ConnSession struct {
	tunnel     *net.PTCPTunnel
	realm      uint32
	reqTimeout time.Duration
}

func newRPC2Conn(tunnel *net.PTCPTunnel) (*ConnSession, func(), error) {
	var lastErr error
	for _, port := range tunnel.HTTPTryPorts() {
		if c, closeFn, err := newRPC2ConnOnPort(tunnel, port); err == nil {
			return c, closeFn, nil
		} else {
			lastErr = err
		}
	}
	return nil, nil, lastErr
}

func newRPC2ConnOnPort(tunnel *net.PTCPTunnel, port int) (*ConnSession, func(), error) {
	realm := rand.Uint32()
	if err := tunnel.DoBindToPort(realm, port); err != nil {
		return nil, nil, fmt.Errorf("rpc2 bind port %d: %w", port, err)
	}
	c := &ConnSession{tunnel: tunnel, realm: realm, reqTimeout: 15 * time.Second}
	return c, func() { tunnel.DisconnectRealm(realm) }, nil
}

func (c *ConnSession) Post(path string, payload map[string]any, cookie string) (map[string]any, string, error) {
	raw, _ := json.Marshal(payload)
	var sb strings.Builder
	fmt.Fprintf(&sb, "POST %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nContent-Type: application/json\r\nContent-Length: %d\r\n", path, len(raw))
	if cookie != "" {
		fmt.Fprintf(&sb, "Cookie: %s\r\n", cookie)
	}
	sb.WriteString("\r\n")
	sb.WriteString(string(raw))

	resp, err := c.tunnel.DoHTTPOnRealm(c.realm, []byte(sb.String()), c.reqTimeout)
	if err != nil {
		return nil, "", err
	}
	idx := bytes.Index(resp, []byte("\r\n\r\n"))
	if idx < 0 {
		return nil, "", fmt.Errorf("POST %s: malformed HTTP response", path)
	}
	headers, body := string(resp[:idx]), bytes.TrimSpace(resp[idx+4:])
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		status := headers
		if i := strings.Index(status, "\r\n"); i >= 0 {
			status = status[:i]
		}
		return nil, "", fmt.Errorf("POST %s: bad JSON body (status: %s)", path, status)
	}
	return out, headers, nil
}

func (c *ConnSession) PostMultipart(path string, fields map[string]string, fileField, filename string, fileData []byte, cookie string) (string, string, error) {
	boundary := "rk0wnP4rtB0und4ry7d1a2"
	var form strings.Builder
	for k, v := range fields {
		fmt.Fprintf(&form, "--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n", boundary, k, v)
	}
	fmt.Fprintf(&form, "--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n", boundary, fileField, filename)
	bodyPart := append([]byte(form.String()), fileData...)
	bodyPart = append(bodyPart, []byte(fmt.Sprintf("\r\n--%s--\r\n", boundary))...)

	var hb strings.Builder
	fmt.Fprintf(&hb, "POST %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: multipart/form-data; boundary=%s\r\nContent-Length: %d\r\n", path, boundary, len(bodyPart))
	if cookie != "" {
		fmt.Fprintf(&hb, "Cookie: %s\r\n", cookie)
	}
	hb.WriteString("\r\n")
	payload := append([]byte(hb.String()), bodyPart...)

	c.reqTimeout = 12 * time.Second
	resp, err := c.tunnel.DoHTTPOnRealm(c.realm, payload, c.reqTimeout)
	if err != nil {
		return "", "", err
	}
	idx := bytes.Index(resp, []byte("\r\n\r\n"))
	if idx < 0 {
		return "", "", fmt.Errorf("POST %s: malformed HTTP response", path)
	}
	headers, body := string(resp[:idx]), string(bytes.TrimSpace(resp[idx+4:]))
	status := headers
	if i := strings.Index(status, "\r\n"); i >= 0 {
		status = status[:i]
	}
	return body, status, nil
}

func (c *ConnSession) HTTPGet(path, cookie string) (string, string, error) {
	var hb strings.Builder
	fmt.Fprintf(&hb, "GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\nUser-Agent: Mozilla/5.0\r\n", path)
	if cookie != "" {
		fmt.Fprintf(&hb, "Cookie: %s\r\n", cookie)
	}
	hb.WriteString("\r\n")
	resp, err := c.tunnel.DoHTTPOnRealm(c.realm, []byte(hb.String()), 5*time.Second)
	if err != nil {
		return "", "", err
	}
	idx := bytes.Index(resp, []byte("\r\n\r\n"))
	if idx < 0 {
		return "", "", fmt.Errorf("GET %s: malformed HTTP response", path)
	}
	headers, body := string(resp[:idx]), string(bytes.TrimSpace(resp[idx+4:]))
	status := headers
	if i := strings.Index(status, "\r\n"); i >= 0 {
		status = status[:i]
	}
	return body, status, nil
}

func rpc2SessionCookie(headers string) string {
	for _, line := range strings.Split(headers, "\r\n") {
		lower := strings.ToLower(line)
		if !strings.HasPrefix(lower, "set-cookie:") {
			continue
		}
		val := strings.TrimSpace(line[len("set-cookie:"):])
		if i := strings.Index(val, ";"); i >= 0 {
			val = val[:i]
		}
		if strings.HasPrefix(val, "DhWebClientSessionID=") {
			return val
		}
	}
	return ""
}

func RPC2GetTable(conn *ConnSession, sess any, cookie, name string, id int) ([]any, error) {
	r, _, err := conn.Post("/RPC2", map[string]any{
		"method":  "configManager.getConfig",
		"params":  map[string]any{"name": name},
		"id":      id,
		"session": sess,
	}, cookie)
	if err != nil {
		return nil, err
	}
	if ok, _ := r["result"].(bool); !ok {
		return nil, fmt.Errorf("getConfig %s: result false (%v)", name, r["error"])
	}
	params, _ := r["params"].(map[string]any)
	if params == nil {
		if arr, ok := r["params"].([]any); ok {
			return arr, nil
		}
		return nil, fmt.Errorf("getConfig %s: no params", name)
	}
	switch t := params["table"].(type) {
	case []any:
		return t, nil
	case map[string]any:
		return []any{t}, nil
	default:
		return nil, fmt.Errorf("getConfig %s: unexpected table shape", name)
	}
}

func NewRPC2Session(tunnel *net.PTCPTunnel, login, pass string) (*Session, error) {
	conn, closeConn, err := newRPC2Conn(tunnel)
	if err != nil {
		return nil, err
	}

	emptyLogin := func(id int) (map[string]any, string, error) {
		return conn.Post("/RPC2_Login", map[string]any{
			"method": "global.login",
			"params": map[string]any{
				"userName":   login,
				"password":   "",
				"clientType": "Web3.0",
				"loginType":  "Direct",
			},
			"id":      id,
			"session": 0,
		}, "")
	}
	r1, headers, err := emptyLogin(1)
	if err != nil {
		closeConn()
		return nil, err
	}
	cookie := rpc2SessionCookie(headers)

	var sess any
	if ok, _ := r1["result"].(bool); ok {
		if r2, h2, err2 := emptyLogin(1); err2 == nil {
			if res2, _ := r2["result"].(bool); !res2 {
				r1 = r2
				if c := rpc2SessionCookie(h2); c != "" {
					cookie = c
				}
			}
		}
		if ok, _ := r1["result"].(bool); ok {
			sess = r1["session"]
		}
	}

	if sess == nil {
		params, _ := r1["params"].(map[string]any)
		realm, _ := params["realm"].(string)
		random, _ := params["random"].(string)
		sessTmp := r1["session"]
		if realm == "" || random == "" {
			closeConn()
			return nil, fmt.Errorf("RPC2 login: no challenge received")
		}
		r2, headers2, err := conn.Post("/RPC2_Login", map[string]any{
			"method": "global.login",
			"params": map[string]any{
				"userName":      login,
				"password":      net.StandardRPCHash(login, pass, realm, random),
				"clientType":    "Web3.0",
				"loginType":     "Direct",
				"authorityType": "Default",
			},
			"id":      2,
			"session": sessTmp,
		}, cookie)
		if err != nil {
			closeConn()
			return nil, err
		}
		if c := rpc2SessionCookie(headers2); c != "" {
			cookie = c
		}
		if ok, _ := r2["result"].(bool); !ok {
			closeConn()
			return nil, fmt.Errorf("RPC2 login rejected (%v)", r2["error"])
		}
		sess = r2["session"]
	}

	return &Session{
		Get: func(name string, id int) (*ConfigData, error) {
			t, err := RPC2GetTable(conn, sess, cookie, name, id)
			if err != nil {
				return nil, err
			}
			return &ConfigData{Nested: t}, nil
		},
		SetBoth: func(ctOut, vwOut []any) error {
			return RPC2MulticallSet(conn, sess, cookie, ctOut, vwOut)
		},
		Conn:   conn,
		Sess:   sess,
		Cookie: cookie,
		Close:  closeConn,
	}, nil
}

func NewDHIPSession(tunnel *net.PTCPTunnel, port int, login, pass string) (*Session, error) {
	dh, err := tunnel.NewDHIPClientOnPort(port)
	if err != nil {
		return nil, err
	}
	if err := dh.LoginNormal(login, pass); err != nil {
		dh.Close()
		return nil, fmt.Errorf("dhip login: %w", err)
	}
	return &Session{
		Get: func(name string, id int) (*ConfigData, error) {
			t, err := DHIPGetTable(dh, name, id)
			if err != nil {
				return nil, err
			}
			return &ConfigData{Nested: t}, nil
		},
		SetBoth: func(ctOut, vwOut []any) error {
			return DHIPMulticallSet(dh, ctOut, vwOut)
		},
		Close: func() { dh.Close() },
	}, nil
}

type ConfigData struct {
	Nested []any
}

type Session struct {
	Get     func(name string, id int) (*ConfigData, error)
	SetBoth func(ctOut, vwOut []any) error
	Close   func()
	Conn    *ConnSession
	Sess    any
	Cookie  string
}

func checkMulticallResult(r map[string]any) error {
	if ok, _ := r["result"].(bool); !ok {
		return fmt.Errorf("multicall: result false (%v)", r["error"])
	}
	params, _ := r["params"].([]any)
	if params == nil {
		return nil
	}
	for _, raw := range params {
		m, _ := raw.(map[string]any)
		if m == nil {
			continue
		}
		if ok, _ := m["result"].(bool); !ok {
			return fmt.Errorf("multicall call id=%v failed (%v)", m["id"], m["error"])
		}
	}
	return nil
}

func multicallSetCalls(sess any, ctOut, vwOut []any) []any {
	var calls []any
	if len(ctOut) > 0 {
		calls = append(calls, map[string]any{
			"method": "configManager.setConfig",
			"params": map[string]any{"name": "ChannelTitle", "table": ctOut, "options": []any{}},
			"id":     41, "session": sess,
		})
	}
	if len(vwOut) > 0 {
		calls = append(calls, map[string]any{
			"method": "configManager.setConfig",
			"params": map[string]any{"name": "VideoWidget", "table": vwOut, "options": []any{}},
			"id":     42, "session": sess,
		})
	}
	return calls
}

func RPC2MulticallSet(conn *ConnSession, sess any, cookie string, ctOut, vwOut []any) error {
	calls := multicallSetCalls(sess, ctOut, vwOut)
	if len(calls) == 0 {
		return fmt.Errorf("nothing to set")
	}
	conn.reqTimeout = 45 * time.Second
	r, _, err := conn.Post("/RPC2", map[string]any{
		"method": "system.multicall", "params": calls, "id": 40, "session": sess,
	}, cookie)
	if err != nil {
		return err
	}
	return checkMulticallResult(r)
}

func DHIPMulticallSet(dh *net.DHIPClient, ctOut, vwOut []any) error {
	sess := dh.Session()
	calls := multicallSetCalls(sess, ctOut, vwOut)
	if len(calls) == 0 {
		return fmt.Errorf("nothing to set")
	}
	r, err := dh.Call("system.multicall", calls, 40, nil, nil)
	if err != nil {
		return err
	}
	return checkMulticallResult(r)
}
