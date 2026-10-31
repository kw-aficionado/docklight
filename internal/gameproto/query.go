package gameproto

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

type Result struct {
	Online  int      `json:"online"`
	Max     int      `json:"max"`
	Names   []string `json:"names,omitempty"`
	Version string   `json:"version,omitempty"`
}

func Minecraft(ctx context.Context, host string, port int) (Result, error) {
	var out Result
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		return out, fmt.Errorf("Minecraft status query could not connect to port %d", port)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	addr := []byte(host)
	var handshake bytes.Buffer
	writeVarInt(&handshake, 0)
	writeVarInt(&handshake, 760)
	writeVarInt(&handshake, len(addr))
	handshake.Write(addr)
	_ = binary.Write(&handshake, binary.BigEndian, uint16(port))
	writeVarInt(&handshake, 1)
	if err = writePacket(conn, handshake.Bytes()); err != nil {
		return out, err
	}
	if err = writePacket(conn, []byte{0}); err != nil {
		return out, err
	}
	packet, err := readPacket(bufio.NewReader(conn), 1<<20)
	if err != nil {
		return out, fmt.Errorf("Minecraft server did not return a status response: %w", err)
	}
	r := bytes.NewReader(packet)
	id, err := readVarInt(r)
	if err != nil || id != 0 {
		return out, errors.New("Minecraft server returned an invalid status packet")
	}
	n, err := readVarInt(r)
	if err != nil || n < 0 || n > r.Len() {
		return out, errors.New("Minecraft server returned an invalid status payload")
	}
	raw := make([]byte, n)
	if _, err = io.ReadFull(r, raw); err != nil {
		return out, err
	}
	var status struct {
		Version struct {
			Name string `json:"name"`
		} `json:"version"`
		Players struct {
			Online int `json:"online"`
			Max    int `json:"max"`
			Sample []struct {
				Name string `json:"name"`
			} `json:"sample"`
		} `json:"players"`
	}
	if err = json.Unmarshal(raw, &status); err != nil {
		return out, errors.New("Minecraft server returned malformed status data")
	}
	out.Online = status.Players.Online
	out.Max = status.Players.Max
	out.Version = status.Version.Name
	for _, x := range status.Players.Sample {
		out.Names = append(out.Names, x.Name)
	}
	return out, nil
}

func Bedrock(ctx context.Context, host string, port int) (Result, error) {
	var out Result
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, strconv.Itoa(port)), 2*time.Second)
	if err != nil {
		return out, fmt.Errorf("Bedrock status query could not connect to UDP port %d", port)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	var ping bytes.Buffer
	ping.WriteByte(0x01)
	_ = binary.Write(&ping, binary.BigEndian, time.Now().UnixMilli())
	ping.Write(raknetMagic)
	_ = binary.Write(&ping, binary.BigEndian, uint64(0x5947474452494c))
	if _, err = conn.Write(ping.Bytes()); err != nil {
		return out, err
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return out, fmt.Errorf("Bedrock server did not answer the UDP query; enable query on the server")
	}
	if n < 43 || buf[0] != 0x1c {
		return out, errors.New("Bedrock server returned an invalid RakNet pong")
	}
	length := int(binary.BigEndian.Uint16(buf[41:43]))
	if length < 0 || length > n-43 {
		return out, errors.New("Bedrock server returned an invalid server description")
	}
	fields := strings.Split(string(buf[43:43+length]), ";")
	if len(fields) < 6 || fields[0] != "MCPE" {
		return out, errors.New("Bedrock server description did not include player counts")
	}
	out.Online, _ = strconv.Atoi(fields[4])
	out.Max, _ = strconv.Atoi(fields[5])
	if len(fields) > 3 {
		out.Version = fields[3]
	}
	return out, nil
}

var raknetMagic = []byte{0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78}

func A2S(ctx context.Context, host string, port int) (Result, error) {
	var out Result
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil {
		return out, fmt.Errorf("A2S query could not connect to UDP port %d", port)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	packet := append([]byte{0xff, 0xff, 0xff, 0xff, 0x54}, []byte("Source Engine Query")...)
	packet = append(packet, 0)
	if _, err = conn.Write(packet); err != nil {
		return out, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return out, errors.New("game server did not answer the A2S query; verify the query port and firewall")
	}
	if n < 5 {
		return out, errors.New("game server returned an incomplete A2S response")
	}
	if buf[4] == 0x41 {
		if n < 9 {
			return out, errors.New("game server returned an incomplete A2S challenge")
		}
		packet = append([]byte{0xff, 0xff, 0xff, 0xff, 0x54}, []byte("Source Engine Query")...)
		packet = append(packet, 0)
		packet = append(packet, buf[5:9]...)
		if _, err = conn.Write(packet); err != nil {
			return out, err
		}
		n, err = conn.Read(buf)
		if err != nil {
			return out, errors.New("game server did not answer the A2S challenge")
		}
	}
	if n < 11 || buf[4] != 0x49 {
		return out, errors.New("game server returned an unsupported A2S info packet")
	}
	r := bytes.NewReader(buf[6:n])
	_, _ = readCString(r)
	_, _ = readCString(r)
	_, _ = readCString(r)
	game, err := readCString(r)
	if err != nil {
		return out, err
	}
	var appID uint16
	_ = binary.Read(r, binary.LittleEndian, &appID)
	players, err := r.ReadByte()
	if err != nil {
		return out, err
	}
	maxPlayers, err := r.ReadByte()
	if err != nil {
		return out, err
	}
	out.Online = int(players)
	out.Max = int(maxPlayers)
	out.Version = game
	return out, nil
}
func readCString(r *bytes.Reader) (string, error) {
	var b []byte
	for r.Len() > 0 {
		c, e := r.ReadByte()
		if e != nil {
			return "", e
		}
		if c == 0 {
			return string(b), nil
		}
		b = append(b, c)
	}
	return "", io.ErrUnexpectedEOF
}

func writePacket(w io.Writer, p []byte) error {
	var h bytes.Buffer
	writeVarInt(&h, len(p))
	if _, e := w.Write(h.Bytes()); e != nil {
		return e
	}
	_, e := w.Write(p)
	return e
}
func readPacket(r *bufio.Reader, max int) ([]byte, error) {
	n, e := readVarInt(r)
	if e != nil {
		return nil, e
	}
	if n < 0 || n > max {
		return nil, errors.New("status response exceeds size limit")
	}
	b := make([]byte, n)
	_, e = io.ReadFull(r, b)
	return b, e
}
func writeVarInt(w io.Writer, value int) {
	v := uint32(value)
	for {
		if v&^0x7f == 0 {
			_, _ = w.Write([]byte{byte(v)})
			return
		}
		_, _ = w.Write([]byte{byte(v&0x7f | 0x80)})
		v >>= 7
	}
}
func readVarInt(r io.ByteReader) (int, error) {
	n := 0
	for i := 0; i < 5; i++ {
		b, e := r.ReadByte()
		if e != nil {
			return 0, e
		}
		n |= int(b&0x7f) << (7 * i)
		if b&0x80 == 0 {
			return n, nil
		}
	}
	return 0, errors.New("invalid VarInt")
}

func SourceRCON(ctx context.Context, host string, port int, password, command string) (string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		return "", fmt.Errorf("RCON could not connect on host port %d; check that the rune enables RCON", port)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err = sendRCON(conn, 1, 3, password); err != nil {
		return "", err
	}
	id, typ, _, err := readRCON(conn)
	if err != nil {
		return "", fmt.Errorf("RCON authentication response was not received: %w", err)
	}
	if id == -1 || typ != 2 {
		return "", errors.New("RCON rejected the configured password; update the server RCON setting and restart")
	}
	if err = sendRCON(conn, 2, 2, command); err != nil {
		return "", err
	}
	_, typ, response, err := readRCON(conn)
	if err != nil {
		return "", fmt.Errorf("RCON command response was not received: %w", err)
	}
	if typ != 0 {
		return "", errors.New("RCON returned an unexpected response type")
	}
	return response, nil
}
func sendRCON(w io.Writer, id, typ int32, body string) error {
	n := int32(len(body) + 10)
	buf := make([]byte, 4+int(n))
	binary.LittleEndian.PutUint32(buf, uint32(n))
	binary.LittleEndian.PutUint32(buf[4:], uint32(id))
	binary.LittleEndian.PutUint32(buf[8:], uint32(typ))
	copy(buf[12:], body)
	buf[len(buf)-2] = 0
	buf[len(buf)-1] = 0
	_, err := w.Write(buf)
	return err
}
func readRCON(r io.Reader) (int32, int32, string, error) {
	var n int32
	if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
		return 0, 0, "", err
	}
	if n < 10 || n > 1<<20 {
		return 0, 0, "", errors.New("invalid RCON packet length")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, 0, "", err
	}
	id := int32(binary.LittleEndian.Uint32(buf))
	typ := int32(binary.LittleEndian.Uint32(buf[4:]))
	return id, typ, string(bytes.TrimRight(buf[8:], "\x00")), nil
}
