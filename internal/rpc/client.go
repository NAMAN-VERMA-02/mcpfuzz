// Package rpc speaks newline-delimited JSON-RPC 2.0 to an MCP server over stdio.
//
// The server is untrusted. Every read is bounded, every call has a deadline, and
// closing a client kills the server's whole process tree.
package rpc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"strconv"
	"sync"
	"time"
)

const (
	// MaxMessage is the largest message accepted from the server.
	MaxMessage = 4 << 20
	// MaxPayload is the largest message sent to the server.
	MaxPayload = 1 << 20
)

var (
	ErrTimeout   = errors.New("no response before the deadline")
	ErrExited    = errors.New("server exited")
	ErrTooLarge  = errors.New("message over the size limit")
	ErrWrongID   = errors.New("response id does not match the request")
	ErrMalformed = errors.New("malformed JSON-RPC response")
)

// Error is a JSON-RPC error object.
type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Message is one JSON-RPC message read from the server.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
	Raw     []byte          `json:"-"`
}

// Client is one running server process.
type Client struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	msgs    chan *Message
	done    chan struct{} // closed when stdout ends
	quit    chan struct{} // closed by Close, so the reader never blocks forever
	readErr error         // why stdout ended; read only after done is closed
	stderr  *tail
	cleanup func()
	nextID  int
	stale   map[string]bool // ids whose answers no longer matter

	mu        sync.Mutex
	closed    bool
	junk      int    // lines on stdout that were not JSON
	junkFirst string // the first of them
}

var (
	liveMu sync.Mutex
	live   = map[*Client]bool{}
)

// Start runs argv with piped stdio. cleanup, if not nil, runs once when the client closes.
func Start(argv []string, cleanup func()) (*Client, error) {
	if len(argv) == 0 {
		return nil, errors.New("empty server command")
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	setGroup(cmd)
	cmd.WaitDelay = 2 * time.Second // a grandchild holding stderr must not block Wait
	c := &Client{cmd: cmd, msgs: make(chan *Message, 64), done: make(chan struct{}), quit: make(chan struct{}),
		stderr: &tail{max: 8 << 10}, cleanup: cleanup, stale: map[string]bool{}}
	cmd.Stderr = c.stderr
	var err error
	if c.stdin, err = cmd.StdinPipe(); err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	liveMu.Lock()
	live[c] = true
	liveMu.Unlock()
	go c.read(stdout)
	return c, nil
}

// CloseAll closes every running client, for use on interrupt.
func CloseAll() {
	liveMu.Lock()
	cs := make([]*Client, 0, len(live))
	for c := range live {
		cs = append(cs, c)
	}
	liveMu.Unlock()
	for _, c := range cs {
		c.Close()
	}
}

func (c *Client) read(r io.Reader) {
	defer close(c.done)
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := readLine(br, MaxMessage)
		if err != nil {
			c.readErr = err
			if err == ErrTooLarge {
				c.kill()
			}
			return
		}
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		m := &Message{Raw: line}
		if json.Unmarshal(line, m) != nil {
			c.mu.Lock()
			if c.junk == 0 {
				c.junkFirst = string(line)
			}
			c.junk++
			c.mu.Unlock()
			continue
		}
		select {
		case c.msgs <- m:
		case <-c.quit:
			return
		}
	}
}

func readLine(r *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(line)+len(chunk) > max {
			return nil, ErrTooLarge
		}
		line = append(line, chunk...)
		switch {
		case err == bufio.ErrBufferFull:
			continue
		case err == io.EOF && len(line) > 0:
			return line, nil
		case err != nil:
			return nil, err
		}
		return line, nil
	}
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\r' || b[0] == '\n') {
		b = b[1:]
	}
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\t' || b[len(b)-1] == '\r' || b[len(b)-1] == '\n') {
		b = b[:len(b)-1]
	}
	return b
}

// Call sends a request and waits for its response. A non-nil Message comes back
// with ErrWrongID and ErrMalformed so the caller can report what the server sent.
func (c *Client) Call(method string, params any, timeout time.Duration) (*Message, error) {
	c.nextID++
	id := c.nextID
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	if err := c.write(body, timeout); err != nil {
		return nil, err
	}
	want := strconv.Itoa(id)
	for {
		m, err := c.next(deadline)
		if err != nil {
			if err == ErrTimeout {
				c.stale[want] = true
			}
			return nil, err
		}
		if m.Method != "" {
			c.answerServer(m)
			continue
		}
		got := string(m.ID)
		if c.stale[got] {
			continue
		}
		if got != want {
			return m, ErrWrongID
		}
		if m.JSONRPC != "2.0" || (m.Result == nil) == (m.Error == nil) {
			return m, ErrMalformed
		}
		return m, nil
	}
}

// Notify sends a notification.
func (c *Client) Notify(method string, params any) error {
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
	if err != nil {
		return err
	}
	return c.write(body, 5*time.Second)
}

// SendRaw writes one line as is and returns the first response, if any arrives
// before the timeout. Silence is not an error here: ErrTimeout just means none came.
func (c *Client) SendRaw(line []byte, timeout time.Duration) (*Message, error) {
	deadline := time.Now().Add(timeout)
	if err := c.write(line, timeout); err != nil {
		return nil, err
	}
	for {
		m, err := c.next(deadline)
		if err != nil {
			return nil, err
		}
		if m.Method != "" {
			c.answerServer(m)
			continue
		}
		return m, nil
	}
}

// Ignore drops any later response that carries this raw id.
func (c *Client) Ignore(rawID string) { c.stale[rawID] = true }

// answerServer refuses requests from the server; the scanner offers no client features.
func (c *Client) answerServer(m *Message) {
	if len(m.ID) == 0 {
		return
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID,
		"error": map[string]any{"code": -32601, "message": "mcpfuzz offers no client features"}})
	_ = c.write(body, time.Second)
}

func (c *Client) next(deadline time.Time) (*Message, error) {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case m := <-c.msgs:
		return m, nil
	case <-c.done:
		select { // drain anything read before stdout closed
		case m := <-c.msgs:
			return m, nil
		default:
		}
		if c.readErr == ErrTooLarge {
			return nil, ErrTooLarge
		}
		return nil, ErrExited
	case <-timer.C:
		return nil, ErrTimeout
	}
}

func (c *Client) write(body []byte, timeout time.Duration) error {
	if len(body) > MaxPayload {
		return ErrTooLarge
	}
	errc := make(chan error, 1)
	go func() {
		_, err := c.stdin.Write(append(body, '\n'))
		errc <- err
	}()
	select {
	case err := <-errc:
		if err != nil {
			return ErrExited
		}
		return nil
	case <-time.After(timeout):
		c.kill() // a server that stops reading stdin would block us forever
		return ErrTimeout
	}
}

// Alive reports whether the server's stdout is still open.
func (c *Client) Alive() bool {
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}

// Junk returns how many non-JSON lines the server wrote to stdout, and the first one.
func (c *Client) Junk() (int, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.junk, c.junkFirst
}

// Stderr returns the tail of what the server wrote to stderr.
func (c *Client) Stderr() string { return c.stderr.String() }

// ExitStatus describes how the process ended; call it after Close.
func (c *Client) ExitStatus() string {
	if c.cmd.ProcessState == nil {
		return "unknown"
	}
	return c.cmd.ProcessState.String()
}

func (c *Client) kill() {
	if c.cmd.Process != nil {
		killTree(c.cmd.Process)
	}
}

// Close ends the server: EOF on stdin first, then the whole process tree is killed.
func (c *Client) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()
	close(c.quit)
	_ = c.stdin.Close()
	select {
	case <-c.done:
	case <-time.After(time.Second):
	}
	c.kill()
	_ = c.cmd.Wait()
	if c.cleanup != nil {
		c.cleanup()
	}
	liveMu.Lock()
	delete(live, c)
	liveMu.Unlock()
}

// tail keeps the last max bytes written to it.
type tail struct {
	mu  sync.Mutex
	max int
	b   []byte
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.b = append(t.b, p...)
	if len(t.b) > t.max {
		t.b = t.b[len(t.b)-t.max:]
	}
	return len(p), nil
}

func (t *tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.b)
}
