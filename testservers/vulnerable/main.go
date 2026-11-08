// Command vulnerable is a deliberately broken MCP server for testing mcpfuzz.
// It has path traversal, shell injection, a poisoned tool description and
// conformance bugs. Run it only inside the isolated container mcpfuzz builds.
package main

import "github.com/NAMAN-VERMA-02/mcpfuzz/testservers/internal/server"

func main() { server.Main(true) }
