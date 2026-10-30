package ingest

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestScanFromIncremental(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	alert := `{"event_type":"alert","x":1}` + "\n"
	flow := `{"event_type":"flow","x":2}` + "\n"
	partial := `{"event_type":"dns"`

	collect := func(offset int64) ([]string, Result, int64) {
		t.Helper()
		var got []string
		res, next, err := scanFrom(path, offset, func(line []byte) error {
			got = append(got, string(line))
			return nil
		})
		if err != nil {
			t.Fatalf("scanFrom: %v", err)
		}
		return got, res, next
	}

	if err := os.WriteFile(path, []byte(alert+flow+partial), 0o644); err != nil {
		t.Fatal(err)
	}
	got, res, off := collect(0)
	if len(got) != 2 || res.Events != 2 || res.Alerts != 1 {
		t.Fatalf("first pass got=%v res=%+v", got, res)
	}
	if off != int64(len(alert)+len(flow)) {
		t.Fatalf("offset must stop before partial line, got %d", off)
	}

	// 半行写完后下一轮只读到它
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`,"x":3}` + "\r\n\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	got, res, off2 := collect(off)
	if len(got) != 1 || got[0] != `{"event_type":"dns","x":3}` || res.Alerts != 0 {
		t.Fatalf("second pass got=%v res=%+v", got, res)
	}
	st, _ := os.Stat(path)
	if off2 != st.Size() {
		t.Fatalf("offset %d != size %d", off2, st.Size())
	}

	// 无新数据：offset 不变
	got, _, off3 := collect(off2)
	if len(got) != 0 || off3 != off2 {
		t.Fatalf("idle pass got=%v off=%d", got, off3)
	}

	// 截断/轮转：从头读
	if err := os.WriteFile(path, []byte(flow), 0o644); err != nil {
		t.Fatal(err)
	}
	got, _, off4 := collect(off3)
	if len(got) != 1 || off4 != int64(len(flow)) {
		t.Fatalf("after truncate got=%v off=%d", got, off4)
	}
}

func TestScanFromHandlerErrorSkips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	if err := os.WriteFile(path, []byte("bad\n"+`{"event_type":"alert"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, _, err := scanFrom(path, 0, func(line []byte) error {
		if string(line) == "bad" {
			return errors.New("parse")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Events != 2 || res.Skipped != 1 || res.Alerts != 1 {
		t.Fatalf("res=%+v", res)
	}
}

func TestScanFromLongLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	long := make([]byte, 3<<20)
	for i := range long {
		long[i] = 'a'
	}
	if err := os.WriteFile(path, append(long, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	var n int
	_, off, err := scanFrom(path, 0, func(line []byte) error { n = len(line); return nil })
	if err != nil || n != len(long) || off != int64(len(long)+1) {
		t.Fatalf("n=%d off=%d err=%v", n, off, err)
	}
}
