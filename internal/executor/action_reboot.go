// Package executor provides implementations for action executors.
package executor

import (
	"context"
	"fmt"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	sysreboot "github.com/manchtools/power-manage-sdk/sys/reboot"
)

// executeReboot schedules a system reboot in 5 minutes.
func (e *Executor) executeReboot(ctx context.Context) (*pb.CommandOutput, error) {
	// Best-effort heads-up to logged-in users; never block the reboot on it.
	notifyAll(ctx, "System Reboot", "This system will reboot in 5 minutes. Please save your work.")

	rb, err := sysreboot.New(executorRunner)
	if err != nil {
		return nil, fmt.Errorf("failed to build reboot manager: %w", err)
	}
	if err := rb.Schedule(ctx, sysreboot.ScheduleOptions{Delay: "+5", Message: "Power Manage: scheduled reboot"}); err != nil {
		return nil, fmt.Errorf("failed to schedule reboot: %w", err)
	}
	return &pb.CommandOutput{Stdout: "Reboot scheduled in 5 minutes\n"}, nil
}
