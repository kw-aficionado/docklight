package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	streamHeaderSize = 16
	streamChunkSize  = 64 * 1024
	maxChunkSize     = 1024 * 1024
)

var streamMagic = [4]byte{'D', 'L', 'B', '1'}

func deriveKey(key []byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("docklight-backup-v1\x00"))
	_, _ = h.Write(key)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// StreamWriter encrypts a sequence of independently authenticated chunks.
// The authenticated empty final chunk makes truncation detectable without
// buffering the archive in memory.
type StreamWriter struct {
	w         io.Writer
	gcm       cipher.AEAD
	header    [streamHeaderSize]byte
	chunkSize int
	sequence  uint64
	buffer    []byte
	closed    bool
	err       error
}

func NewStreamWriter(w io.Writer, key []byte) (*StreamWriter, error) {
	if w == nil || len(key) == 0 {
		return nil, errors.New("backup writer and encryption key are required")
	}
	digest := deriveKey(key)
	block, err := aes.NewCipher(digest[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	var header [streamHeaderSize]byte
	copy(header[:4], streamMagic[:])
	if _, err = rand.Read(header[4:12]); err != nil {
		return nil, fmt.Errorf("generate backup nonce: %w", err)
	}
	binary.BigEndian.PutUint32(header[12:], streamChunkSize)
	if err = writeAll(w, header[:]); err != nil {
		return nil, fmt.Errorf("write backup header: %w", err)
	}
	return &StreamWriter{w: w, gcm: gcm, header: header, chunkSize: streamChunkSize, buffer: make([]byte, 0, streamChunkSize)}, nil
}

func (w *StreamWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("write to closed backup stream")
	}
	if w.err != nil {
		return 0, w.err
	}
	written := 0
	for len(p) > 0 {
		remaining := w.chunkSize - len(w.buffer)
		n := len(p)
		if n > remaining {
			n = remaining
		}
		w.buffer = append(w.buffer, p[:n]...)
		p = p[n:]
		written += n
		if len(w.buffer) == w.chunkSize {
			if w.err = w.writeFrame(w.buffer); w.err != nil {
				return written, w.err
			}
			w.buffer = w.buffer[:0]
		}
	}
	return written, nil
}

func (w *StreamWriter) Close() error {
	if w.closed {
		return w.err
	}
	w.closed = true
	if w.err != nil {
		return w.err
	}
	if len(w.buffer) > 0 {
		w.err = w.writeFrame(w.buffer)
		if w.err != nil {
			return w.err
		}
	}
	w.err = w.writeFrame(nil)
	return w.err
}

func (w *StreamWriter) writeFrame(plain []byte) error {
	if w.sequence > uint64(^uint32(0)) {
		return errors.New("backup archive exceeds the encrypted stream limit")
	}
	nonce := streamNonce(w.header, uint32(w.sequence), w.gcm.NonceSize())
	aad := streamAAD(w.header, uint32(w.sequence))
	ciphertext := w.gcm.Seal(nil, nonce, plain, aad)
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(ciphertext)))
	if err := writeAll(w.w, size[:]); err != nil {
		return fmt.Errorf("write encrypted backup frame: %w", err)
	}
	if err := writeAll(w.w, ciphertext); err != nil {
		return fmt.Errorf("write encrypted backup data: %w", err)
	}
	w.sequence++
	return nil
}

// StreamReader authenticates each chunk before returning its plaintext.
type StreamReader struct {
	r         io.Reader
	gcm       cipher.AEAD
	header    [streamHeaderSize]byte
	chunkSize uint32
	sequence  uint64
	buffer    []byte
	final     bool
	err       error
}

func NewStreamReader(r io.Reader, key []byte) (*StreamReader, error) {
	if r == nil || len(key) == 0 {
		return nil, errors.New("backup reader and decryption key are required")
	}
	s := &StreamReader{r: r}
	if _, err := io.ReadFull(r, s.header[:]); err != nil {
		return nil, fmt.Errorf("read backup header: %w", err)
	}
	if string(s.header[:4]) != string(streamMagic[:]) {
		return nil, errors.New("file is not a Docklight backup")
	}
	s.chunkSize = binary.BigEndian.Uint32(s.header[12:])
	if s.chunkSize == 0 || s.chunkSize > maxChunkSize {
		return nil, errors.New("backup stream has an unsupported chunk size")
	}
	digest := deriveKey(key)
	block, err := aes.NewCipher(digest[:])
	if err != nil {
		return nil, err
	}
	s.gcm, err = cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (r *StreamReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.buffer) > 0 {
		n := copy(p, r.buffer)
		r.buffer = r.buffer[n:]
		return n, nil
	}
	if r.err != nil {
		return 0, r.err
	}
	if r.final {
		return 0, io.EOF
	}
	if r.sequence > uint64(^uint32(0)) {
		r.err = errors.New("backup archive exceeds the encrypted stream limit")
		return 0, r.err
	}
	var frameSize [4]byte
	if _, err := io.ReadFull(r.r, frameSize[:]); err != nil {
		r.err = fmt.Errorf("backup archive is truncated before its authenticated end: %w", err)
		return 0, r.err
	}
	n := binary.BigEndian.Uint32(frameSize[:])
	if n < uint32(r.gcm.Overhead()) || n > r.chunkSize+uint32(r.gcm.Overhead()) {
		r.err = errors.New("backup archive contains an invalid encrypted frame size")
		return 0, r.err
	}
	ciphertext := make([]byte, n)
	if _, err := io.ReadFull(r.r, ciphertext); err != nil {
		r.err = fmt.Errorf("backup archive is truncated inside an encrypted frame: %w", err)
		return 0, r.err
	}
	nonce := streamNonce(r.header, uint32(r.sequence), r.gcm.NonceSize())
	plain, err := r.gcm.Open(nil, nonce, ciphertext, streamAAD(r.header, uint32(r.sequence)))
	if err != nil {
		r.err = errors.New("backup archive authentication failed; the file may be damaged or the encryption key changed")
		return 0, r.err
	}
	r.sequence++
	if len(plain) == 0 {
		var trailing [1]byte
		count, tailErr := io.ReadFull(r.r, trailing[:])
		if count != 0 {
			r.err = errors.New("backup archive contains data after its authenticated end")
			return 0, r.err
		}
		if tailErr != io.EOF {
			r.err = fmt.Errorf("read backup end marker: %w", tailErr)
			return 0, r.err
		}
		r.final = true
		return 0, io.EOF
	}
	if uint32(len(plain)) > r.chunkSize {
		r.err = errors.New("backup archive contains an oversized plaintext frame")
		return 0, r.err
	}
	r.buffer = plain
	n = uint32(copy(p, r.buffer))
	r.buffer = r.buffer[n:]
	return int(n), nil
}

func streamNonce(header [streamHeaderSize]byte, sequence uint32, size int) []byte {
	nonce := make([]byte, size)
	copy(nonce, header[4:12])
	binary.BigEndian.PutUint32(nonce[8:], sequence)
	return nonce
}

func streamAAD(header [streamHeaderSize]byte, sequence uint32) []byte {
	aad := make([]byte, streamHeaderSize+4)
	copy(aad, header[:])
	binary.BigEndian.PutUint32(aad[streamHeaderSize:], sequence)
	return aad
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
