package gameproto

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMinecraftStatusReturnsExpectedPlayerCount(t *testing.T) {
	requireLocalNetwork(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port, _ := strconv.Atoi(strings.Split(ln.Addr().String(), ":")[1])
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		br := bufio.NewReader(c)
		_, _ = readPacket(br, 4096)
		_, _ = readPacket(br, 4096)
		payload := []byte(`{"version":{"name":"1.21.4"},"players":{"online":7,"max":20,"sample":[{"name":"player-a"}]}}`)
		var body bytes.Buffer
		writeVarInt(&body, 0)
		writeVarInt(&body, len(payload))
		body.Write(payload)
		_ = writePacket(c, body.Bytes())
	}()
	got, err := Minecraft(context.Background(), "127.0.0.1", port)
	if err != nil {
		t.Fatal(err)
	}
	if got.Online != 7 || got.Max != 20 || got.Version != "1.21.4" || len(got.Names) != 1 || got.Names[0] != "player-a" {
		t.Fatalf("unexpected Minecraft response: %+v", got)
	}
}

func TestBedrockRaknetPongParsesCounts(t *testing.T) {
	requireLocalNetwork(t)
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	port := conn.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, 256)
		_, peer, e := conn.ReadFromUDP(buf)
		if e != nil {
			return
		}
		desc := []byte("MCPE;Test Bedrock;685;1.21;5;30;1;world;Survival;1;19132;19133;")
		pong := make([]byte, 43+len(desc))
		pong[0] = 0x1c
		copy(pong[17:33], raknetMagic)
		binary.BigEndian.PutUint16(pong[41:43], uint16(len(desc)))
		copy(pong[43:], desc)
		_, _ = conn.WriteToUDP(pong, peer)
	}()
	got, err := Bedrock(context.Background(), "127.0.0.1", port)
	if err != nil {
		t.Fatal(err)
	}
	if got.Online != 5 || got.Max != 30 || got.Version != "1.21" {
		t.Fatalf("unexpected Bedrock response: %+v", got)
	}
}

func TestA2SInfoParsesCounts(t *testing.T) {
	requireLocalNetwork(t)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	port := conn.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, 256)
		_, peer, e := conn.ReadFromUDP(buf)
		if e != nil {
			return
		}
		var p bytes.Buffer
		p.Write([]byte{0xff, 0xff, 0xff, 0xff, 0x49, 17})
		for _, s := range []string{"Factorio", "map", "folder", "Factorio"} {
			p.WriteString(s)
			p.WriteByte(0)
		}
		_ = binary.Write(&p, binary.LittleEndian, uint16(440))
		p.Write([]byte{3, 12, 0})
		_ = binary.Write(&p, binary.LittleEndian, uint16(0))
		p.Write([]byte{0, 0})
		_, _ = conn.WriteToUDP(p.Bytes(), peer)
	}()
	got, err := A2S(context.Background(), "127.0.0.1", port)
	if err != nil {
		t.Fatal(err)
	}
	if got.Online != 3 || got.Max != 12 || got.Version != "Factorio" {
		t.Fatalf("unexpected A2S response: %+v", got)
	}
}

func TestSourceRCONAuthenticatesAndRunsCommand(t *testing.T) {
	requireLocalNetwork(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port, _ := strconv.Atoi(strings.Split(ln.Addr().String(), ":")[1])
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		id, typ, pass, e := readRCON(c)
		if e != nil || id != 1 || typ != 3 || pass != "secret" {
			return
		}
		writeTestRCON(c, 1, 2, "")
		id, typ, command, e := readRCON(c)
		if e == nil && id == 2 && typ == 2 && command == "list" {
			writeTestRCON(c, 2, 0, "There are 2 of 20 players online")
		}
	}()
	got, err := SourceRCON(context.Background(), "127.0.0.1", port, "secret", "list")
	if err != nil {
		t.Fatal(err)
	}
	if got != "There are 2 of 20 players online" {
		t.Fatalf("unexpected RCON response %q", got)
	}
}
func writeTestRCON(w io.Writer, id, typ int32, body string) {
	size := int32(len(body) + 10)
	b := make([]byte, 4+size)
	binary.LittleEndian.PutUint32(b, uint32(size))
	binary.LittleEndian.PutUint32(b[4:], uint32(id))
	binary.LittleEndian.PutUint32(b[8:], uint32(typ))
	copy(b[12:], body)
	_, _ = w.Write(b)
}

func requireLocalNetwork(t *testing.T) {
	t.Helper()
	if os.Getenv("YGGDRASIL_TEST_NETWORK") != "1" {
		t.Skip("set YGGDRASIL_TEST_NETWORK=1 to run local TCP/UDP protocol fixtures")
	}
}

func TestVarIntBounds(t *testing.T) {
	if _, err := readVarInt(bytes.NewReader([]byte{0x80, 0x80, 0x80, 0x80, 0x80})); err == nil {
		t.Fatal("expected malformed VarInt to fail")
	}
	var b bytes.Buffer
	writeVarInt(&b, 300)
	got, err := readVarInt(bytes.NewReader(b.Bytes()))
	if err != nil || got != 300 {
		t.Fatalf("VarInt: got %d, %v", got, err)
	}
	_ = fmt.Sprint(got)
}
