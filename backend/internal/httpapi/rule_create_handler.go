package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"

	"spycam/backend/internal/rules"
	"spycam/backend/internal/store/gen"
)

// 自定义规则允许的动作与协议（白名单，规则体其余内容由 suricata -T 兜底）。
var (
	customActions   = map[string]bool{"alert": true}
	customProtocols = map[string]bool{"tcp": true, "udp": true, "icmp": true, "http": true, "dns": true, "tls": true, "ssh": true}
	customStages    = map[string]bool{"recon": true, "bruteforce": true, "exploit": true, "c2": true, "exfil": true}
)

type createRuleRequest struct {
	Action   string `json:"action"`   // alert
	Protocol string `json:"protocol"` // tcp/udp/http/dns...
	SrcIP    string `json:"src_ip"`   // 支持 any / 单 IP / CIDR
	SrcPort  string `json:"src_port"` // any / 22 / [1:200] / [80,443]
	DstIP    string `json:"dst_ip"`
	DstPort  string `json:"dst_port"`
	Content  string `json:"content"`           // 可选：匹配内容（自动 nocase）
	Direction string `json:"direction"`        // -> 或 <>
	Msg      string `json:"msg"`               // 中文描述（进 msg 字段）
	Stage    string `json:"stage"`             // recon/bruteforce/exploit/c2/exfil
	Severity int    `json:"severity"`          // 1-3
	Threshold struct {
		Count   int `json:"count"`   // 0 = 不启用频次阈值
		Seconds int `json:"seconds"` // 时间窗
	} `json:"threshold"`
	MitreTactic    string `json:"mitre_tactic"`
	MitreTechnique string `json:"mitre_technique"`
}

// handleCreateRule 自定义规则创建（对标 Scirius：UI 内新建规则 → 校验 → 热加载生效）。
// 应对"新攻击手法出现"的运营场景：安全分析师无需改代码、无需重启引擎。
func (s *Server) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	var req createRuleRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}

	// 1. 字段白名单校验
	req.Action = strings.ToLower(strings.TrimSpace(req.Action))
	req.Protocol = strings.ToLower(strings.TrimSpace(req.Protocol))
	if !customActions[req.Action] {
		writeErr(w, http.StatusBadRequest, "action 仅支持 alert")
		return
	}
	if !customProtocols[req.Protocol] {
		writeErr(w, http.StatusBadRequest, "protocol 仅支持 tcp/udp/icmp/http/dns/tls/ssh")
		return
	}
	if !customStages[req.Stage] {
		writeErr(w, http.StatusBadRequest, "stage 仅支持 recon/bruteforce/exploit/c2/exfil")
		return
	}
	req.Direction = strings.TrimSpace(req.Direction)
	if req.Direction != "->" && req.Direction != "<>" {
		req.Direction = "->"
	}
	if req.Msg == "" || len(req.Msg) > 100 {
		writeErr(w, http.StatusBadRequest, "msg 必填且 ≤100 字符")
		return
	}
	if req.SrcIP == "" || req.SrcPort == "" || req.DstIP == "" || req.DstPort == "" {
		writeErr(w, http.StatusBadRequest, "src_ip/src_port/dst_ip/dst_port 必填")
		return
	}
	if err := validateRuleHeaderFields(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Severity < 1 || req.Severity > 3 {
		req.Severity = 2
	}
	// 内容里的双引号会破坏规则语法，直接拒绝
	if strings.ContainsAny(req.Content, `"\\`) {
		writeErr(w, http.StatusBadRequest, "content 不能包含双引号或反斜杠")
		return
	}

	// 2. 组装规则文本（sid 由服务端分配，2000000+ 为自定义段）
	// 注意：Suricata msg 仅支持可打印 ASCII，中文描述不入规则体，
	// 存入 DB 的 msg 列供界面展示；规则内用 ASCII 短语。
	nextSid, err := gen.New(s.pool).NextCustomSid(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "alloc sid failed")
		return
	}
	sid := int64(nextSid)
	ruleMsg := asciiFallback(req.Msg, sid)

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s %s %s %s %s (msg:\"%s\"; ",
		req.Action, req.Protocol, req.SrcIP, req.SrcPort, req.Direction, req.DstIP, req.DstPort, ruleMsg)
	if req.Protocol == "http" || req.Protocol == "dns" || req.Protocol == "tls" {
		fmt.Fprintf(&b, "flow:established,to_server; ")
	}
	if req.Content != "" {
		fmt.Fprintf(&b, "content:\"%s\"; nocase; ", req.Content)
	}
	if req.Threshold.Count > 0 && req.Threshold.Seconds > 0 {
		fmt.Fprintf(&b, "detection_filter:track by_src, count %d, seconds %d; ",
			req.Threshold.Count, req.Threshold.Seconds)
	}
	mitre := req.MitreTactic
	if mitre == "" {
		mitre = "TA0006 Credential Access"
	}
	technique := req.MitreTechnique
	if technique == "" {
		technique = "Custom Detection"
	}
	fmt.Fprintf(&b, "classtype:custom; metadata:stage %s, mitre_tactic %s, mitre_technique %s, author analyst; sid:%d; rev:1;)",
		req.Stage, mitre, technique, sid)

	raw := b.String()

	// 3. 本地快速校验（单行/头格式/sid），再交给 suricata -T 兜底
	if _, err := rules.ValidateLine(raw); err != nil {
		writeErr(w, http.StatusBadRequest, "规则语法校验失败: "+err.Error())
		return
	}

	// 4. 写库 + 生成规则文件 + 校验 + 热重载（与启停同一链路，失败回滚）
	severity := pgtype.Int4{Int32: int32(req.Severity), Valid: true}
	classType := pgtype.Text{String: "custom", Valid: true}
	stage := pgtype.Text{String: req.Stage, Valid: true}
	mitreT := pgtype.Text{String: mitre, Valid: true}
	mitreTech := pgtype.Text{String: technique, Valid: true}
	created, err := gen.New(s.pool).CreateRule(r.Context(), gen.CreateRuleParams{
		Sid:            sid,
		Raw:            raw,
		Msg:            req.Msg,
		Classtype:      classType,
		Severity:       severity,
		Stage:          stage,
		MitreTactic:    mitreT,
		MitreTechnique: mitreTech,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "save rule failed")
		return
	}
	if err := s.regenerateAndReload(r); err != nil {
		// 回滚：禁用刚插入的规则并重新生成规则文件，否则坏规则留在 rules-active 里会让后续每次重载都失败
		_ = gen.New(s.pool).SetRuleEnabled(r.Context(), gen.SetRuleEnabledParams{Sid: created.Sid, Enabled: false})
		if enabled, lerr := gen.New(s.pool).ListEnabledRules(r.Context()); lerr == nil {
			_ = rules.GenerateActiveFile(s.cfg.RulesActiveDir, enabled)
		}
		s.audit(r.Context(), actor(r), auditRuleCreate, strconv.FormatInt(created.Sid, 10),
			map[string]any{"raw": raw, "result": "rolled_back", "error": err.Error()})
		writeErr(w, http.StatusBadGateway, "引擎校验/重载失败，规则已回滚: "+err.Error())
		return
	}

	version := s.recordRuleRevision(r.Context(), actor(r), map[string]any{"op": "create", "sid": created.Sid})
	s.audit(r.Context(), actor(r), auditRuleCreate, strconv.FormatInt(created.Sid, 10),
		map[string]any{"raw": raw, "result": "applied", "ruleset_version": version})
	writeJSON(w, http.StatusCreated, map[string]any{"sid": created.Sid, "raw": raw, "reloaded": true, "ruleset_version": version})
}

// 规则头与 metadata 字段格式白名单（架构设计 §10 规则内容注入防护）：
// 这些字段直接拼进规则文本，若含空格、分号、括号、引号可注入额外关键字或改变规则结构。
var (
	// 地址：any / $HOME_NET 变量 / IPv4 / IPv6 / CIDR，允许 ! 取反与 [a,b] 列表
	ruleAddrRe = regexp.MustCompile(`^(any|!?\$[A-Z_]+|!?\[?[0-9A-Fa-f:.,/!]+\]?)$`)
	// 端口：any / 单端口 / 范围 a:b / 列表 [a,b]，允许 ! 取反
	rulePortRe = regexp.MustCompile(`^(any|!?\$[A-Z_]+|!?\[?[0-9:,!]+\]?)$`)
	// metadata 值：字母数字、空格、点、连字符、下划线；不允许分号、逗号、引号、括号
	ruleMetaRe = regexp.MustCompile(`^[A-Za-z0-9 ._-]{0,64}$`)
)

func validateRuleHeaderFields(req *createRuleRequest) error {
	req.SrcIP, req.DstIP = strings.TrimSpace(req.SrcIP), strings.TrimSpace(req.DstIP)
	req.SrcPort, req.DstPort = strings.TrimSpace(req.SrcPort), strings.TrimSpace(req.DstPort)
	req.MitreTactic, req.MitreTechnique = strings.TrimSpace(req.MitreTactic), strings.TrimSpace(req.MitreTechnique)
	for name, v := range map[string]string{"src_ip": req.SrcIP, "dst_ip": req.DstIP} {
		if len(v) > 128 || !ruleAddrRe.MatchString(v) {
			return fmt.Errorf("%s 格式非法：仅支持 any、$HOME_NET、IP、CIDR 或 [a,b] 列表", name)
		}
	}
	for name, v := range map[string]string{"src_port": req.SrcPort, "dst_port": req.DstPort} {
		if len(v) > 64 || !rulePortRe.MatchString(v) {
			return fmt.Errorf("%s 格式非法：仅支持 any、端口号、范围 a:b 或 [a,b] 列表", name)
		}
	}
	for name, v := range map[string]string{"mitre_tactic": req.MitreTactic, "mitre_technique": req.MitreTechnique} {
		if !ruleMetaRe.MatchString(v) {
			return fmt.Errorf("%s 只能包含字母、数字、空格、点、连字符、下划线（≤64 字符）", name)
		}
	}
	return nil
}

// asciiFallback 把中文描述转成规则内可用的 ASCII msg：
// 保留 ASCII 字符，非 ASCII 用「自定义规则-<sid>」形式替代，保证引擎兼容。
func asciiFallback(msg string, sid int64) string {
	var b strings.Builder
	for _, r := range msg {
		// 双引号/分号/反斜杠会提前结束 msg 字符串或注入新关键字，一律丢弃
		if r >= 32 && r < 127 && r != '"' && r != ';' && r != '\\' {
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return fmt.Sprintf("Custom rule %d (see UI description)", sid)
	}
	if len(out) > 80 {
		out = out[:80]
	}
	return out
}

// regenerateAndReload 重新生成 rules-active 并触发引擎热重载（供创建/启停共用）。
func (s *Server) regenerateAndReload(r *http.Request) error {
	enabled, err := gen.New(s.pool).ListEnabledRules(r.Context())
	if err != nil {
		return fmt.Errorf("list enabled: %w", err)
	}
	if err := rules.GenerateActiveFile(s.cfg.RulesActiveDir, enabled); err != nil {
		return fmt.Errorf("generate file: %w", err)
	}
	if err := s.agent.Reload(r.Context()); err != nil {
		return fmt.Errorf("reload: %w", err)
	}
	return nil
}
