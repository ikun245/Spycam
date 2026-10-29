package rules

import "testing"

func TestValidateLine(t *testing.T) {
	valid := `alert tcp any any -> $HOME_NET 22 (msg:"SSH bruteforce"; flags:S; detection_filter:track by_src, count 10, seconds 60; sid:1000002; rev:1;)`
	tests := []struct {
		name    string
		line    string
		wantSID int64
		wantErr bool
	}{
		{"合法规则", valid, 1000002, false},
		{"注释行跳过", `# comment`, 0, true},
		{"空行跳过", ``, 0, true},
		{"缺 sid", `alert tcp any any -> any 80 (msg:"x";)`, 0, true},
		{"sid 超出本地范围", `alert tcp any any -> any 80 (msg:"x"; sid:1;)`, 0, true},
		{"动作不允许", `drop tcp any any -> any 80 (sid:1000001;)`, 0, true},
		{"多行拒绝", valid + "\n" + valid, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sid, err := ValidateLine(tt.line)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got sid=%d", sid)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if sid != tt.wantSID {
				t.Errorf("sid = %d, want %d", sid, tt.wantSID)
			}
		})
	}
}
