package agent

import (
	"strings"
	"testing"
)

// 硬尾巴守门测试（v0.4.63）：扫描器优先与漏洞覆盖矩阵是代码注入
// 的提示词，不随 UI 改词消失；这里锁住关键锚点，防止后续重构把它们弄丢。
func TestScannerAndCoverageTails(t *testing.T) {
	w := workerSystem("", "", "/tmp", "/tmp/run")
	for _, want := range []string{"扫描器优先", "ffuf -u", "/opt/SecLists", "nuclei -u", "sqlmap -u", "技能路由"} {
		if !strings.Contains(w, want) {
			t.Errorf("worker system prompt missing %q", want)
		}
	}
	// nuclei 提示词的准确性：v3.11.1 既无 -random-agent 也无 -user-agent，
	// 示例里给了这个 flag，弱模型照抄就是 flag provided but not defined。
	if strings.Contains(w, "random-agent") {
		t.Errorf("worker 提示词不得含 random-agent（nuclei v3.11.1 无此 flag，照抄必报错）")
	}
	// 出口代理口径：说明 scan_with_nuclei 自动带 -proxy、手工命令才需自己加。
	for _, want := range []string{"-proxy", "scan_with_nuclei"} {
		if !strings.Contains(w, want) {
			t.Errorf("worker system prompt missing %q", want)
		}
	}
	p := plannerSystem("目标", "/tmp", "/tmp/run")
	for _, want := range []string{"漏洞覆盖矩阵", "SQL 注入", "SSRF/回连", "文件上传", "弱口令", "ffuf/gobuster", "授权边界与复核优先"} {
		if !strings.Contains(p, want) {
			t.Errorf("planner system prompt missing %q", want)
		}
	}
}
