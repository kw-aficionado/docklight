package backup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestRemoteClientsValidateHostsPathsAndSMBShares(t *testing.T) {
	fingerprint := "SHA256:" + strings.Repeat("A", 43)
	sftpClient, err := NewSFTPClient("[2001:db8::5]", 0, "backup-user", "password", fingerprint, "snapshots/daily")
	if err != nil {
		t.Fatal(err)
	}
	if sftpClient.address != "[2001:db8::5]:22" {
		t.Fatalf("SFTP address=%q", sftpClient.address)
	}
	if _, err = NewSFTPClient("host/path", 22, "backup-user", "password", fingerprint, ""); err == nil {
		t.Fatal("accepted an SFTP host containing a path")
	}
	for _, host := range []string{"[host", "host]", "host:22", "host/path"} {
		if _, err = NewSFTPClient(host, 22, "backup-user", "password", fingerprint, ""); err == nil {
			t.Errorf("accepted invalid SFTP host %q", host)
		}
	}
	if _, err = NewSFTPClient("host", 22, "backup-user", "password", fingerprint, "../escape"); err == nil {
		t.Fatal("accepted a traversal prefix")
	}
	if _, err = NewSFTPClient("host", 22, "backup-user", "password", "SHA256:invalid", ""); err == nil {
		t.Fatal("accepted an invalid SSH SHA-256 host-key fingerprint")
	}
	if _, err = remoteObjectPath("snapshots", "../escape.dlbak"); err == nil {
		t.Fatal("accepted a traversal object key")
	}
	smbClient, err := NewSMBClient("nas.example.test", 0, "game-backups", "backup-user", "password", "docklight")
	if err != nil {
		t.Fatal(err)
	}
	if smbClient.address != "nas.example.test:445" {
		t.Fatalf("SMB address=%q", smbClient.address)
	}
	for _, share := range []string{"../share", ".", ".."} {
		if _, err = NewSMBClient("nas.example.test", 445, share, "backup-user", "password", ""); err == nil {
			t.Errorf("accepted invalid SMB share %q", share)
		}
	}
}

func TestSFTPClientUploadsDownloadsAndDeletesOverPasswordSSH(t *testing.T) {
	root := t.TempDir()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	var authCount atomic.Int32
	serverConfig := &ssh.ServerConfig{PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if meta.User() != "backup-user" || string(password) != "correct horse battery staple" {
			return nil, errors.New("authentication rejected")
		}
		authCount.Add(1)
		return nil, nil
	}}
	serverConfig.AddHostKey(signer)
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())
	client, err := NewSFTPClient("sftp.test", 22, "backup-user", "correct horse battery staple", fingerprint, "")
	if err != nil {
		t.Fatal(err)
	}
	client.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rawClient, rawServer := net.Pipe()
		clientSide, serverSide := bufferedPipe(rawClient), bufferedPipe(rawServer)
		go serveTestSFTP(serverSide, serverConfig, root)
		return clientSide, nil
	}

	const key = "docklight/server-1/backup-1.dlbak"
	payload := []byte("verified encrypted archive bytes")
	if err = client.Put(context.Background(), key, bytes.NewReader(payload)); err != nil {
		t.Fatalf("upload: %v", err)
	}
	remoteFile := filepath.Join(root, filepath.FromSlash(key))
	saved, err := os.ReadFile(remoteFile)
	if err != nil || !bytes.Equal(saved, payload) {
		t.Fatalf("stored remote bytes=%q err=%v", saved, err)
	}
	var downloaded bytes.Buffer
	if err = client.GetObject(context.Background(), key, &downloaded); err != nil {
		t.Fatalf("download: %v", err)
	}
	if !bytes.Equal(downloaded.Bytes(), payload) {
		t.Fatalf("downloaded bytes=%q", downloaded.Bytes())
	}
	if err = client.DeleteObject(context.Background(), key); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err = os.Stat(remoteFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("remote file still exists or stat failed unexpectedly: %v", err)
	}
	if got := authCount.Load(); got != 3 {
		t.Fatalf("password authentication calls=%d, want 3", got)
	}

	_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongSigner, err := ssh.NewSignerFromKey(wrongPrivate)
	if err != nil {
		t.Fatal(err)
	}
	wrongClient, err := NewSFTPClient("sftp.test", 22, "backup-user", "correct horse battery staple", ssh.FingerprintSHA256(wrongSigner.PublicKey()), "")
	if err != nil {
		t.Fatal(err)
	}
	wrongClient.dial = client.dial
	if err = wrongClient.Put(context.Background(), key, bytes.NewReader(payload)); err == nil || !strings.Contains(err.Error(), "host key does not match") {
		t.Fatalf("wrong SSH host key was not rejected clearly: %v", err)
	}
	if got := authCount.Load(); got != 3 {
		t.Fatalf("password was sent before host-key verification: authentication calls=%d", got)
	}
}

type bufferedPipeConn struct {
	net.Conn
	writes chan []byte
	closed chan struct{}
	once   sync.Once
}

func bufferedPipe(conn net.Conn) *bufferedPipeConn {
	buffered := &bufferedPipeConn{Conn: conn, writes: make(chan []byte, 64), closed: make(chan struct{})}
	go func() {
		for {
			select {
			case payload := <-buffered.writes:
				if _, err := conn.Write(payload); err != nil {
					_ = buffered.Close()
					return
				}
			case <-buffered.closed:
				return
			}
		}
	}()
	return buffered
}

func (c *bufferedPipeConn) Write(payload []byte) (int, error) {
	copyOfPayload := bytes.Clone(payload)
	select {
	case c.writes <- copyOfPayload:
		return len(payload), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *bufferedPipeConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func serveTestSFTP(conn net.Conn, config *ssh.ServerConfig, root string) {
	defer conn.Close()
	_, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(requests)
	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported channel")
			continue
		}
		channel, channelRequests, acceptErr := newChannel.Accept()
		if acceptErr != nil {
			continue
		}
		go func() {
			defer channel.Close()
			for request := range channelRequests {
				if request.Type != "subsystem" {
					_ = request.Reply(false, nil)
					continue
				}
				var subsystem struct{ Name string }
				if ssh.Unmarshal(request.Payload, &subsystem) != nil || subsystem.Name != "sftp" {
					_ = request.Reply(false, nil)
					continue
				}
				_ = request.Reply(true, nil)
				server, serverErr := sftp.NewServer(channel, sftp.WithServerWorkingDirectory(root))
				if serverErr != nil {
					return
				}
				serveErr := server.Serve()
				if serveErr != nil && !errors.Is(serveErr, io.EOF) {
					_ = server.Close()
					return
				}
				_ = server.Close()
				return
			}
		}()
	}
}
