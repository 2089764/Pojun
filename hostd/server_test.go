package hostd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 回归：任务的父 ctx 必须来自进程生命周期，**不能**是 HTTP 请求的 ctx。
// 曾经把 r.Context() 传进 Start，handler 一返回 ctx 就被取消，排队中的任务
// 立刻变成 cancelled（实测在真机上装 hashcat 时踩到）。
func TestJobNotCancelledByRequestContext(t *testing.T) {
	// 清空 PATH：所有工具都被探测为「缺失」，且真去执行时也解析不到可执行文件，
	// 于是任务会快速失败到 failed —— 既与宿主机装了什么无关，也不产生任何副作用。
	t.Setenv("PATH", "")

	srv := NewServer(context.Background(), log.New(io.Discard, "", 0))
	mux := srv.Handler()

	// 一个「已经开始就结束」的请求 ctx，模拟 handler 返回后的状态。
	reqCtx, cancelReq := context.WithCancel(context.Background())
	body, _ := json.Marshal(map[string]string{"tool_id": "masscan"})
	req := httptest.NewRequest(http.MethodPost, "/jobs", bytes.NewReader(body)).WithContext(reqCtx)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	// 先取消请求 ctx，再调用：如果实现里误用了请求 ctx，任务必然立即被取消
	cancelReq()
	mux.ServeHTTP(w, req)

	if len(srv.jobs) == 0 {
		t.Fatalf("应当受理任务，却没有任何任务；响应=%s", w.Body.String())
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, j := range srv.List() {
			j.mu.Lock()
			st := j.State
			j.mu.Unlock()
			if st == StateCancelled {
				t.Fatalf("任务被请求 ctx 取消（回归）：state=%s log=%q", st, j.Log)
			}
			if st == StateDone || st == StateFailed {
				return // 终态且不是 cancelled，符合预期
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("任务在 10s 内未达终态")
}

// healthz 是探活契约，前端据此决定是否显示「安装」按钮。
func TestHealthz(t *testing.T) {
	srv := NewServer(context.Background(), log.New(io.Discard, "", 0))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("healthz 应 200，得到 %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "pojun-hostd") {
		t.Errorf("healthz 响应异常: %s", w.Body.String())
	}
}

// 审计 B9：自我换装拒绝降级目标——助手版本高于目标 tag 时 400，不被主程序的
// 版本对齐循环（可能跑在被手动回滚的主程序上）拽回旧版。
func TestSelfUpgradeRejectsDowngrade(t *testing.T) {
	srv := NewServer(context.Background(), log.New(io.Discard, "", 0))
	srv.Version = "v0.4.89"
	post := func(tag string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"tag": tag})
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/self-upgrade", bytes.NewReader(body)))
		return w
	}
	if w := post("v0.4.88"); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "拒绝降级") {
		t.Fatalf("降级请求应 400：code=%d body=%s", w.Code, w.Body.String())
	}
	// 升级与同版本仍然放行（走到下载前的最后一关——这里换装CAS抢锁后 202 即返回）。
	if w := post("v0.4.90"); w.Code != http.StatusAccepted {
		t.Fatalf("升级请求应放行 202：code=%d body=%s", w.Code, w.Body.String())
	}
	// 上面 202 已占用 upgrading 锁，清理：直接等 CAS 恢复（goroutine 会下载失败）。
	for i := 0; i < 100 && !srv.upgrading.CompareAndSwap(true, false); i++ {
		time.Sleep(10 * time.Millisecond)
	}
}
