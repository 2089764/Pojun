package agent

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/chu0119/pojun/vulnintel"
)

// CWE→方法论 skill 联动（M1 闭环）：relatedSkillsFor 按命中 CWE 去重返回
// skill 名单；未注入索引或无命中时返回 nil——工具输出里不出现 related_skills，
// 联动是纯增量，不能让既有形状变化。
func TestRelatedSkillsFor(t *testing.T) {
	// 未注入索引：恒为 nil。
	if got := relatedSkillsFor([]string{"CWE-89"}); got != nil {
		t.Fatalf("未注入索引时应返回 nil，got=%v", got)
	}

	SetCweSkillIndex(map[string][]string{
		"CWE-89":  {"inj-skill"},
		"CWE-862": {"authz-skill"},
		"CWE-639": {"authz-skill"},
	})
	t.Cleanup(func() { SetCweSkillIndex(nil) })

	// 单 CWE 命中。
	if got := relatedSkillsFor([]string{"CWE-89"}); !reflect.DeepEqual(got, []string{"inj-skill"}) {
		t.Fatalf("CWE-89 → %v", got)
	}
	// 多 CWE 去重：两个 CWE 指向同一 skill 时只出现一次；大小写不敏感。
	got := relatedSkillsFor([]string{"CWE-862", "cwe-639"})
	if !reflect.DeepEqual(got, []string{"authz-skill"}) {
		t.Fatalf("CWE-862+cwe-639 → %v，应为去重后的 [authz-skill]", got)
	}
	// 无命中返回 nil。
	if got := relatedSkillsFor([]string{"CWE-999"}); got != nil {
		t.Fatalf("无命中应返回 nil，got=%v", got)
	}
}

// 联动字段必须是「无则缺失」：不带 related_skills 的 get_vuln 输出形状与
// 既有调用方（提示词里写的字段名）保持一致。
func TestVulnDetailWithSkillsOmitsEmptyFields(t *testing.T) {
	b, err := json.Marshal(vulnDetailWithSkills{VulnDetail: nil})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["related_skills"]; ok {
		t.Fatal("无联动时 related_skills 不应出现在输出里")
	}
}

// TestNucleiScanArgsCarriesEgressProxy 锁住出口接线：egressProxy 必须原样进
// ScanArgs.Proxy。回归（漏接）时这条立刻红，而不是等线上扫描默默直连。
func TestNucleiScanArgsCarriesEgressProxy(t *testing.T) {
	ts := &ToolSet{egressProxy: "http://127.0.0.1:8788"}
	a := ts.nucleiScanArgs("https://t/", "CVE-2021-41773", "critical,high")
	if a.Proxy != "http://127.0.0.1:8788" {
		t.Fatalf("Proxy = %q, want 出口代理原值", a.Proxy)
	}
	if a.TimeoutTotal != 10*time.Minute {
		t.Fatalf("TimeoutTotal = %v, want 10m", a.TimeoutTotal)
	}
	if a.Target != "https://t/" || a.CVEID != "CVE-2021-41773" || a.Severity != "critical,high" {
		t.Fatalf("入参未透传: %+v", a)
	}
	if empty := (&ToolSet{}).nucleiScanArgs("u", "", ""); empty.Proxy != "" {
		t.Fatalf("空代理应为空串, got %q", empty.Proxy)
	}
}

// TestNucleiBashCommand 在无 nuclei、无 PG 的机器上断言整条命令串：
// -proxy 的相邻位置、逐参数单引号、空代理不发射、含逗号报错。
func TestNucleiBashCommand(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	run, err := nucleiBashCommand(dir, vulnintel.ScanArgs{
		Target:       "https://t/api?a=1&b=2",
		TimeoutTotal: 10 * time.Minute,
		Proxy:        "http://127.0.0.1:8788",
	})
	if err != nil {
		t.Fatal(err)
	}
	// 前缀按实际环境计算：Linux/CI 上 PATH 有 GNU timeout 时会前置
	// "'<timeout>' 600 "（CI 是 ubuntu-latest，必然命中这条分支），
	// 写死 'nuclei' 会让门禁确定性变红。
	wantPrefix := "'nuclei'"
	tp, terr := exec.LookPath("timeout")
	if terr == nil && runtime.GOOS != "windows" {
		wantPrefix = quoteShell(tp) + " 600 'nuclei'"
	}
	if !strings.HasPrefix(run, wantPrefix) {
		t.Fatalf("命令应以 %q 开头, got %q", wantPrefix, run)
	}
	if n := strings.Count(run, "'-proxy'"); n != 1 {
		t.Fatalf("-proxy 应恰好出现一次, got %d: %q", n, run)
	}
	if !strings.Contains(run, "'-proxy' 'http://127.0.0.1:8788'") {
		t.Fatalf("缺少 -proxy 与其值相邻两段: %q", run)
	}
	if !strings.Contains(run, "'https://t/api?a=1&b=2'") {
		t.Fatalf("target 应整体单引号包裹: %q", run)
	}

	// timeout 包裹与 -proxy 的组合路径：30m 必须推导成 1800 秒，不能写死 600。
	// Windows 没有 GNU timeout 分支，推导规则由 vulnintel.TestEffectiveTimeout 覆盖。
	if terr == nil && runtime.GOOS != "windows" {
		run30, err := nucleiBashCommand(dir, vulnintel.ScanArgs{Target: "https://t/", TimeoutTotal: 30 * time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(run30, quoteShell(tp)+" 1800 ") {
			t.Fatalf("30m 应推导为 timeout 1800 秒前缀, got %q", run30)
		}
	}

	run, err = nucleiBashCommand(dir, vulnintel.ScanArgs{Target: "https://t/", TimeoutTotal: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(run, "-proxy") {
		t.Fatalf("无代理命令不应含 -proxy: %q", run)
	}

	if _, err := nucleiBashCommand(dir, vulnintel.ScanArgs{
		Target:       "https://t/",
		TimeoutTotal: 10 * time.Minute,
		Proxy:        "http://a,b:1",
	}); err == nil {
		t.Fatal("含逗号代理应返回错误")
	}
}

// TestNucleiEgressNote 锁住出口排查提示：只有配置代理时才前置，
// 且必须能引导到 proxy_status。
func TestNucleiEgressNote(t *testing.T) {
	if got := nucleiEgressNote(""); got != "" {
		t.Fatalf("空代理应返回空串, got %q", got)
	}
	if got := nucleiEgressNote("   "); got != "" {
		t.Fatalf("空白代理应返回空串, got %q", got)
	}
	got := nucleiEgressNote("http://127.0.0.1:8788")
	if !strings.Contains(got, "-proxy") || !strings.Contains(got, "proxy_status") {
		t.Fatalf("非空代理提示应含 -proxy 与 proxy_status, got %q", got)
	}
}
