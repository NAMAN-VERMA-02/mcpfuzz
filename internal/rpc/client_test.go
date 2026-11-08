package rpc

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	switch os.Getenv("RPC_FAKE") {
	case "huge": // answers with a line over MaxMessage
		bufio.NewReader(os.Stdin).ReadString('\n')
		fmt.Println(`{"jsonrpc":"2.0","id":1,"result":{"x":"` + strings.Repeat("A", MaxMessage) + `"}}`)
		time.Sleep(10 * time.Second)
		os.Exit(0)
	case "exit":
		os.Exit(7)
	case "noread": // never reads stdin, so a big write blocks
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fake(t *testing.T, mode string) *Client {
	t.Setenv("RPC_FAKE", mode)
	c, err := Start([]string{os.Args[0]}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestOversizedResponseIsRefused(t *testing.T) {
	c := fake(t, "huge")
	if _, err := c.Call("x", nil, 5*time.Second); err != ErrTooLarge {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
}

func TestExitIsReported(t *testing.T) {
	c := fake(t, "exit")
	if _, err := c.Call("x", nil, 5*time.Second); err != ErrExited {
		t.Fatalf("got %v, want ErrExited", err)
	}
}

func TestOversizedRequestIsNotSent(t *testing.T) {
	c := fake(t, "noread")
	if _, err := c.Call("x", map[string]string{"a": strings.Repeat("A", MaxPayload)}, time.Second); err != ErrTooLarge {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
}

func TestBlockedWriteTimesOut(t *testing.T) {
	c := fake(t, "noread")
	start := time.Now()
	_, err := c.Call("x", map[string]string{"a": strings.Repeat("A", MaxPayload/2)}, 500*time.Millisecond)
	if err != ErrTimeout || time.Since(start) > 5*time.Second {
		t.Fatalf("got %v after %s, want ErrTimeout promptly", err, time.Since(start))
	}
}
