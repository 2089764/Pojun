package server

import (
	"context"
	"errors"
	"testing"

	"github.com/chu0119/pojun/agent"
)

// TestHandlePlannerRoundOutcomeRegistersSettleBeforeCancelExec 钉住收尾判据的
// 登记顺序：cancelExec 取消的就是本轮 ectx，若先取消再检查 ectx.Err()，goal_met
// 收尾在 met 轮永远登记不上（任务只能等心跳/超时结束）。
func TestHandlePlannerRoundOutcomeRegistersSettleBeforeCancelExec(t *testing.T) {
	e := NewEngine(nil)
	task := &Task{ID: "t1"}
	ectx := e.execContextFor(context.Background(), task.ID)

	e.handlePlannerRoundOutcome(task, 1, nil, plannerRoundOutcome{met: true, reason: "all goals met"}, context.Background(), ectx)

	if reason, _ := task.peekSettle(); reason != "goal_met" {
		t.Fatalf("挂起收尾 reason=%q，期望 goal_met（登记被 cancelExec 遮掉了）", reason)
	}
	if ectx.Err() == nil {
		t.Fatal("判定目标达成后在跑 worker 未被取消")
	}
	if code, _, _, ok := agent.AbortReason(ectx); !ok || code != "goal_met" {
		t.Fatalf("取消原因 code=%q ok=%v，期望 goal_met", code, ok)
	}
}

// TestHandlePlannerRoundOutcomeSkipsSettleAfterExternalCancel 本轮已被外部取消
// （pause / 收尾硬取消）时不得登记收尾：否则 pause 期间攒下的 goal_met 会在
// resume 后立刻把任务收掉。
func TestHandlePlannerRoundOutcomeSkipsSettleAfterExternalCancel(t *testing.T) {
	e := NewEngine(nil)
	task := &Task{ID: "t2"}
	ectx := e.execContextFor(context.Background(), task.ID)
	e.Pause(task.ID, agent.AbortPausedByUser)

	e.handlePlannerRoundOutcome(task, 1, nil, plannerRoundOutcome{met: true, reason: "all goals met"}, context.Background(), ectx)

	if reason, _ := task.peekSettle(); reason != "" {
		t.Fatalf("外部取消后仍登记了收尾 %q", reason)
	}
}

// TestHandlePlannerRoundOutcomeIgnoresGoalMetOnPlannerError 半成功的轮不能用来
// 收尾：Plan 可能在 prove_goal 置位 GoalMet 之后才因 LLM/传输错误返回非 nil err
// （agent/planner.go 直接透传 tsx.GoalMet），此时既不该登记收尾，也不该杀 worker。
func TestHandlePlannerRoundOutcomeIgnoresGoalMetOnPlannerError(t *testing.T) {
	e := NewEngine(nil)
	task := &Task{ID: "t3"}
	ectx := e.execContextFor(context.Background(), task.ID)

	e.handlePlannerRoundOutcome(task, 1, nil, plannerRoundOutcome{met: true, err: errors.New("llm down")}, context.Background(), ectx)

	if reason, _ := task.peekSettle(); reason != "" {
		t.Fatalf("规划出错却登记了收尾 %q", reason)
	}
	if ectx.Err() != nil {
		t.Fatal("规划出错却取消了在跑 worker")
	}
}
