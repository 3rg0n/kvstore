// badclient is a test HTTP client for kvstore e2e testing.
// It is NOT intended to be registered — used to test rejection paths.
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// Unique identity ensures this binary has a different SHA-256 hash than goodclient.
const appIdentity = "badclient-v1"

func main() {
	server := flag.String("server", "http://127.0.0.1:7390", "kvstore server base URL")
	token := flag.String("token", "", "bearer token for authentication")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: badclient [flags] <command> [args]\n")
		fmt.Fprintf(os.Stderr, "Commands: health, get <ns> <key>, set <ns> <key> <value>, list [ns], delete <ns> <key>\n")
		fmt.Fprintf(os.Stderr, "Identity: %s\n", appIdentity)
		os.Exit(2)
	}

	var method, path, body string
	base := strings.TrimRight(*server, "/")

	switch args[0] {
	case "health":
		method, path = "GET", "/api/v1/health"
	case "get":
		if len(args) != 3 {
			fatal("usage: get <namespace> <key>")
		}
		method, path = "GET", fmt.Sprintf("/api/v1/kv/%s/%s", args[1], args[2])
	case "set":
		if len(args) != 4 {
			fatal("usage: set <namespace> <key> <value>")
		}
		method, path = "PUT", fmt.Sprintf("/api/v1/kv/%s/%s", args[1], args[2])
		body = fmt.Sprintf(`{"value":%q}`, args[3])
	case "list":
		method = "GET"
		if len(args) >= 2 {
			path = fmt.Sprintf("/api/v1/kv/%s", args[1])
		} else {
			path = "/api/v1/kv"
		}
	case "delete":
		if len(args) != 3 {
			fatal("usage: delete <namespace> <key>")
		}
		method, path = "DELETE", fmt.Sprintf("/api/v1/kv/%s/%s", args[1], args[2])
	default:
		fatal("unknown command: " + args[0])
	}

	var reqBody io.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, base+path, reqBody)
	if err != nil {
		fatal(err.Error())
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if *token != "" {
		req.Header.Set("Authorization", "Bearer "+*token)
	}

	resp, err := http.DefaultClient.Do(req) //nolint:gosec // test client: URL is intentionally user-provided
	if err != nil {
		fatal(err.Error())
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	fmt.Print(string(respBody))

	if resp.StatusCode >= 400 {
		os.Exit(1)
	}
}

func fatal(msg string) {
	fmt.Fprintf(os.Stderr, "error: %s\n", msg) //nolint:gosec // test client: error output is not HTML
	os.Exit(2)
}
