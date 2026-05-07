// Package executor provides implementations for action executors.
package executor

import (
	"context"
	"fmt"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	sysnotify "github.com/manchtools/power-manage/sdk/go/sys/notify"
	sysreboot "github.com/manchtools/power-manage/sdk/go/sys/reboot"
)

// executeReboot schedules a system reboot in 5 minutes.
func (e *Executor) executeReboot(ctx context.Context) (*pb.CommandOutput, error) {
	sysnotify.NotifyAll(ctx, "System Reboot", "This system will reboot in 5 minutes. Please save your work.")

	if err := sysreboot.Schedule(ctx, "+5", "Power Manage: scheduled reboot"); err != nil {
		return nil, fmt.Errorf("failed to schedule reboot: %w", err)
	}
	return &pb.CommandOutput{Stdout: "Reboot scheduled in 5 minutes\n"}, nil
}
