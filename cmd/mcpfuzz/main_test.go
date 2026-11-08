package main

import (
	"io"
	"strings"
	"testing"
)

// Active mode must refuse to start unless every authorisation flag is given.
func TestActiveNeedsEveryFlag(t *testing.T) {
	for _, args := range []string{
		"--active -- srv",
		"--active --allow-tools a --allowed-root /work -- srv",
		"--active --allow-tools a --i-own-this-target -- srv",
		"--active --allowed-root /work --i-own-this-target -- srv",
		"--allow-tools a -- srv",
		"--active --allow-tools a --allowed-root /work --i-own-this-target",
	} {
		if code := run(strings.Fields(args), io.Discard, io.Discard); code != 3 {
			t.Errorf("%q: exit %d, want 3", args, code)
		}
	}
}
