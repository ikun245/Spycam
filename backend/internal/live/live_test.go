package live

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"spycam/backend/internal/ingest"
)

func TestIDsDeterministicAndDistinct(t *testing.T) {
	uuidRe := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	p1, t1 := IDs("eth0")
	p2, t2 := IDs("eth0")
	p3, t3 := IDs("ens33")
	if p1 != p2 || t1 != t2 {
		t.Fatalf("not deterministic: %s/%s vs %s/%s", p1, t1, p2, t2)
	}
	for _, id := range []string{p1, t1, p3, t3} {
		if !uuidRe.MatchString(id) {
			t.Fatalf("invalid uuid %q", id)
		}
	}
	if p1 == t1 || p1 == p3 || t1 == t3 {
		t.Fatalf("ids collide: %s %s %s %s", p1, t1, p3, t3)
	}
}

// countingRead 只统计完整行，不依赖数据库：与 ingest.scanFile 一样只消费以 '\n' 结尾的行。
func countingRead(seen *[]string) readFn {
	return func(f *os.File, off int64) (ingest.Result, int64, error) {
		var res ingest.Result
		data, err := io.ReadAll(f)
		if err != nil {
			return res, off, err
		}
		// ReadAll 从当前位置读；advance 传入的文件句柄位于开头，按 off 截取
		if int64(len(data)) < off {
			off = 0
		}
		rest := data[off:]
		for {
			i := bytes.IndexByte(rest, '\n')
			if i < 0 {
				break
			}
			*seen = append(*seen, string(rest[:i]))
			res.Events++
			off += int64(i + 1)
			rest = rest[i+1:]
		}
		return res, off, nil
	}
}

func TestAdvanceDrainsRotatedFile(t *testing.T) {
	dir := t.TempDir()
	eve := filepath.Join(dir, "eve.json")
	var seen []string
	read := countingRead(&seen)

	if err := os.WriteFile(eve, []byte("a1\na2\npartial"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, res, err := advance(eve, cursor{}, read)
	if err != nil || res.Events != 2 || c.Off != 6 {
		t.Fatalf("first read: c=%+v res=%+v err=%v", c, res, err)
	}

	// 轮转前旧文件又写完了半行并追加一行；随后改名为 .1，新文件只有一行（比旧 offset 短）
	if err := os.WriteFile(eve, []byte("a1\na2\npartial-done\na3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(eve, eve+rotatedSuffix); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(eve, []byte("b1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, res, err = advance(eve, c, read)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a1", "a2", "partial-done", "a3", "b1"}
	if strings.Join(seen, ",") != strings.Join(want, ",") {
		t.Fatalf("seen %v, want %v", seen, want)
	}
	if res.Events != 3 || c.Off != 3 {
		t.Fatalf("after rotation: c=%+v res=%+v", c, res)
	}
}

func TestParseCursor(t *testing.T) {
	cases := map[string]cursor{
		"":        {},
		"42":      {Off: 42},
		"7:1024":  {Ino: 7, Off: 1024},
		"x:1":     {},
		"-5":      {},
		"3:-1":    {},
		"garbage": {},
	}
	for in, want := range cases {
		if got := parseCursor(in); got != want {
			t.Errorf("parseCursor(%q) = %+v, want %+v", in, got, want)
		}
	}
	if s := (cursor{Ino: 7, Off: 1024}).String(); parseCursor(s) != (cursor{Ino: 7, Off: 1024}) {
		t.Errorf("round trip failed: %s", s)
	}
}
