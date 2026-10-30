package live

import (
	"regexp"
	"testing"
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
