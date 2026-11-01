package backup

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	smb2 "github.com/hirochachacha/go-smb2"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const remoteIOTimeout = 30 * time.Second

// SFTPClient stores backup objects over an SSH password-authenticated SFTP v3
// session and requires an administrator-pinned SHA-256 host-key fingerprint.
type SFTPClient struct {
	address       string
	username      string
	password      string
	hostKeySHA256 string
	prefix        string
	dial          func(context.Context, string, string) (net.Conn, error)
}

func NewSFTPClient(host string, port int, username, password, hostKeySHA256, prefix string) (*SFTPClient, error) {
	host, port, err := normalizeRemoteHost(host, port, 22)
	if err != nil {
		return nil, fmt.Errorf("SFTP %w", err)
	}
	username = strings.TrimSpace(username)
	if username == "" || len(username) > 256 || hasControl(username) {
		return nil, errors.New("SFTP username must contain 1 to 256 printable characters")
	}
	if password == "" || len(password) > 4096 {
		return nil, errors.New("SFTP password must contain 1 to 4096 characters")
	}
	hostKeySHA256, err = normalizeSSHHostKeySHA256(hostKeySHA256)
	if err != nil {
		return nil, err
	}
	prefix, err = normalizeRemotePrefix(prefix)
	if err != nil {
		return nil, fmt.Errorf("SFTP %w", err)
	}
	return &SFTPClient{address: net.JoinHostPort(host, strconv.Itoa(port)), username: username, password: password, hostKeySHA256: hostKeySHA256, prefix: prefix}, nil
}

func normalizeSSHHostKeySHA256(fingerprint string) (string, error) {
	fingerprint = strings.TrimSpace(fingerprint)
	const prefix = "SHA256:"
	if !strings.HasPrefix(fingerprint, prefix) {
		return "", errors.New("enter the SFTP server's SHA-256 host-key fingerprint (SHA256:…)")
	}
	digest, err := base64.RawStdEncoding.Strict().DecodeString(strings.TrimPrefix(fingerprint, prefix))
	if err != nil || len(digest) != sha256.Size {
		return "", errors.New("SFTP host-key fingerprint must be a valid SHA-256 value such as SHA256:…")
	}
	return prefix + base64.RawStdEncoding.EncodeToString(digest), nil
}

func (c *SFTPClient) Put(ctx context.Context, key string, source io.Reader) error {
	if source == nil {
		return errors.New("SFTP upload source is required")
	}
	remote, err := remoteObjectPath(c.prefix, key)
	if err != nil {
		return fmt.Errorf("SFTP %w", err)
	}
	return c.withClient(ctx, func(client *sftp.Client) error {
		if err := client.MkdirAll(path.Dir(remote)); err != nil {
			return fmt.Errorf("create SFTP backup directory: %w", err)
		}
		file, err := client.OpenFile(remote, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		if err != nil {
			return fmt.Errorf("open SFTP backup file: %w", err)
		}
		_, copyErr := io.Copy(file, source)
		closeErr := file.Close()
		if copyErr != nil {
			return fmt.Errorf("write SFTP backup: %w", copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close SFTP backup: %w", closeErr)
		}
		return nil
	})
}

func (c *SFTPClient) PutFile(ctx context.Context, key string, file *os.File) error {
	if file == nil {
		return errors.New("SFTP upload source file is required")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return errors.New("could not rewind SFTP backup source")
	}
	return c.Put(ctx, key, file)
}

func (c *SFTPClient) GetObject(ctx context.Context, key string, destination io.Writer) error {
	if destination == nil {
		return errors.New("SFTP download destination is required")
	}
	remote, err := remoteObjectPath(c.prefix, key)
	if err != nil {
		return fmt.Errorf("SFTP %w", err)
	}
	return c.withClient(ctx, func(client *sftp.Client) error {
		file, err := client.Open(remote)
		if err != nil {
			return fmt.Errorf("open SFTP backup: %w", err)
		}
		_, copyErr := io.Copy(destination, file)
		closeErr := file.Close()
		if copyErr != nil {
			return fmt.Errorf("read SFTP backup: %w", copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close SFTP backup: %w", closeErr)
		}
		return nil
	})
}

func (c *SFTPClient) DeleteObject(ctx context.Context, key string) error {
	remote, err := remoteObjectPath(c.prefix, key)
	if err != nil {
		return fmt.Errorf("SFTP %w", err)
	}
	return c.withClient(ctx, func(client *sftp.Client) error {
		if err := client.Remove(remote); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("delete SFTP backup: %w", err)
		}
		return nil
	})
}

func (c *SFTPClient) withClient(ctx context.Context, operation func(*sftp.Client) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	dial := c.dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: remoteIOTimeout}).DialContext
	}
	conn, err := dial(ctx, "tcp", c.address)
	if err != nil {
		return fmt.Errorf("connect to SFTP host: %w", err)
	}
	done := interruptConnectionOnCancel(ctx, conn)
	defer done()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	hostKeyMismatch := false
	sshConn, channels, requests, err := ssh.NewClientConn(conn, c.address, &ssh.ClientConfig{
		User: c.username,
		Auth: []ssh.AuthMethod{ssh.Password(c.password)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			actual := ssh.FingerprintSHA256(key)
			if subtle.ConstantTimeCompare([]byte(actual), []byte(c.hostKeySHA256)) != 1 {
				hostKeyMismatch = true
				return errors.New("SFTP host-key fingerprint mismatch")
			}
			return nil
		},
		Timeout: remoteIOTimeout,
	})
	if err != nil {
		_ = conn.Close()
		if hostKeyMismatch {
			return errors.New("SFTP host key does not match the configured SHA-256 fingerprint; verify it with the server administrator")
		}
		return errors.New("SFTP authentication or SSH negotiation failed")
	}
	sshClient := ssh.NewClient(sshConn, channels, requests)
	defer sshClient.Close()
	client, err := sftp.NewClient(sshClient)
	if err != nil {
		return fmt.Errorf("start SFTP subsystem: %w", err)
	}
	defer client.Close()
	if err = operation(client); err != nil {
		return err
	}
	return nil
}

// SMBClient stores backup objects on a native SMB2 share using NTLMv2.
type SMBClient struct {
	address  string
	share    string
	username string
	password string
	prefix   string
}

func NewSMBClient(host string, port int, share, username, password, prefix string) (*SMBClient, error) {
	host, port, err := normalizeRemoteHost(host, port, 445)
	if err != nil {
		return nil, fmt.Errorf("SMB %w", err)
	}
	share = strings.TrimSpace(share)
	if share == "" || share == "." || share == ".." || len(share) > 80 || strings.ContainsAny(share, "/\\") || hasControl(share) {
		return nil, errors.New("SMB share name must contain 1 to 80 characters and no path separators")
	}
	username = strings.TrimSpace(username)
	if username == "" || len(username) > 256 || hasControl(username) {
		return nil, errors.New("SMB username must contain 1 to 256 printable characters")
	}
	if password == "" || len(password) > 4096 {
		return nil, errors.New("SMB password must contain 1 to 4096 characters")
	}
	prefix, err = normalizeRemotePrefix(prefix)
	if err != nil {
		return nil, fmt.Errorf("SMB %w", err)
	}
	return &SMBClient{address: net.JoinHostPort(host, strconv.Itoa(port)), share: share, username: username, password: password, prefix: prefix}, nil
}

func (c *SMBClient) Put(ctx context.Context, key string, source io.Reader) error {
	if source == nil {
		return errors.New("SMB upload source is required")
	}
	remote, err := remoteObjectPath(c.prefix, key)
	if err != nil {
		return fmt.Errorf("SMB %w", err)
	}
	return c.withShare(ctx, func(share *smb2.Share) error {
		if err := share.MkdirAll(path.Dir(remote), 0700); err != nil {
			return fmt.Errorf("create SMB backup directory: %w", err)
		}
		file, err := share.OpenFile(remote, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("open SMB backup file: %w", err)
		}
		_, copyErr := io.Copy(file, source)
		closeErr := file.Close()
		if copyErr != nil {
			return fmt.Errorf("write SMB backup: %w", copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close SMB backup: %w", closeErr)
		}
		return nil
	})
}

func (c *SMBClient) PutFile(ctx context.Context, key string, file *os.File) error {
	if file == nil {
		return errors.New("SMB upload source file is required")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return errors.New("could not rewind SMB backup source")
	}
	return c.Put(ctx, key, file)
}

func (c *SMBClient) GetObject(ctx context.Context, key string, destination io.Writer) error {
	if destination == nil {
		return errors.New("SMB download destination is required")
	}
	remote, err := remoteObjectPath(c.prefix, key)
	if err != nil {
		return fmt.Errorf("SMB %w", err)
	}
	return c.withShare(ctx, func(share *smb2.Share) error {
		file, err := share.Open(remote)
		if err != nil {
			return fmt.Errorf("open SMB backup: %w", err)
		}
		_, copyErr := io.Copy(destination, file)
		closeErr := file.Close()
		if copyErr != nil {
			return fmt.Errorf("read SMB backup: %w", copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close SMB backup: %w", closeErr)
		}
		return nil
	})
}

func (c *SMBClient) DeleteObject(ctx context.Context, key string) error {
	remote, err := remoteObjectPath(c.prefix, key)
	if err != nil {
		return fmt.Errorf("SMB %w", err)
	}
	return c.withShare(ctx, func(share *smb2.Share) error {
		if err := share.Remove(remote); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("delete SMB backup: %w", err)
		}
		return nil
	})
}

func (c *SMBClient) withShare(ctx context.Context, operation func(*smb2.Share) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	conn, err := (&net.Dialer{Timeout: remoteIOTimeout}).DialContext(ctx, "tcp", c.address)
	if err != nil {
		return fmt.Errorf("connect to SMB host: %w", err)
	}
	done := interruptConnectionOnCancel(ctx, conn)
	defer done()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	session, err := (&smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: c.username, Password: c.password}}).DialContext(ctx, conn)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("SMB2 authentication failed: %w", err)
	}
	defer conn.Close()
	defer session.Logoff()
	share, err := session.WithContext(ctx).Mount(c.share)
	if err != nil {
		return fmt.Errorf("mount SMB share: %w", err)
	}
	share = share.WithContext(ctx)
	defer share.Umount()
	return operation(share)
}

func normalizeRemoteHost(host string, port, defaultPort int) (string, int, error) {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") != strings.HasSuffix(host, "]") {
		return "", 0, errors.New("host is invalid")
	}
	if strings.HasPrefix(host, "[") {
		host = host[1 : len(host)-1]
	}
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/\\@") || hasControl(host) || strings.IndexFunc(host, func(r rune) bool { return r == ' ' || r == '\t' }) >= 0 {
		return "", 0, errors.New("host is invalid")
	}
	if strings.ContainsAny(host, "[]") || strings.Contains(host, ":") && net.ParseIP(strings.SplitN(host, "%", 2)[0]) == nil {
		return "", 0, errors.New("host is invalid")
	}
	if port == 0 {
		port = defaultPort
	}
	if port < 1 || port > 65535 {
		return "", 0, errors.New("port must be between 1 and 65535")
	}
	return host, port, nil
}

func normalizeRemotePrefix(prefix string) (string, error) {
	prefix = strings.Trim(strings.TrimSpace(prefix), "/")
	if len(prefix) > 256 || strings.ContainsAny(prefix, "\\\x00") || hasControl(prefix) {
		return "", errors.New("prefix must be 256 characters or fewer and cannot contain control characters")
	}
	if prefix == "" {
		return "", nil
	}
	for _, segment := range strings.Split(prefix, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", errors.New("prefix cannot contain empty or dot path segments")
		}
	}
	return prefix, nil
}

func remoteObjectPath(prefix, key string) (string, error) {
	if !validS3ObjectKey(key) {
		return "", errors.New("object key is invalid")
	}
	prefix, err := normalizeRemotePrefix(prefix)
	if err != nil {
		return "", err
	}
	joined := path.Join(prefix, key)
	if joined == "" || joined == "." || strings.HasPrefix(joined, "../") {
		return "", errors.New("object path is invalid")
	}
	return joined, nil
}

func interruptConnectionOnCancel(ctx context.Context, conn net.Conn) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	return func() {
		close(done)
		_ = conn.Close()
	}
}
