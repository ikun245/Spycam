package main

import (
"fmt"
"io"
"net/http"
"os"
"strings"
)

func main() {
token := ""
if b, err := os.ReadFile("/tmp/envdump"); err == nil {
for _, line := range strings.Split(string(b), "\n") {
if strings.HasPrefix(line, "ENGINE_AGENT_TOKEN=") {
token = strings.TrimPrefix(line, "ENGINE_AGENT_TOKEN=")
}
}
}
body := `{"task_id":"9435d7f3-d77a-47e3-af3e-f154809469f2","pcap_id":"cd83fbf0-9e63-4745-8ea9-40d3c73659c0"}`
req, _ := http.NewRequest("POST", "http://suricata:9090/v1/replay", strings.NewReader(body))
req.Header.Set("X-Agent-Token", token)
req.Header.Set("Content-Type", "application/json")
resp, err := http.DefaultClient.Do(req)
if err != nil {
fmt.Println("ERR", err)
return
}
defer resp.Body.Close()
rb, _ := io.ReadAll(resp.Body)
fmt.Println("status:", resp.Status)
fmt.Println("body:", string(rb))
}