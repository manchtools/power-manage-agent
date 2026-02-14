package executor

import (
	"context"
	"fmt"
	"strings"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	sysuser "github.com/manchtools/power-manage/sdk/go/sys/user"
)

// executeGroup manages Linux groups and their members.
func (e *Executor) executeGroup(ctx context.Context, params *pb.GroupParams, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("group params required")
	}
	if !sysuser.IsValidName(params.Name) {
		return nil, false, fmt.Errorf("invalid group name: %q", params.Name)
	}

	for _, m := range params.Members {
		if !sysuser.IsValidName(m) {
			return nil, false, fmt.Errorf("invalid member username: %q", m)
		}
	}

	switch state {
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		return e.removeGroup(ctx, params.Name)
	default:
		return e.setupGroup(ctx, params)
	}
}

// setupGroup creates a group if needed and syncs its membership.
func (e *Executor) setupGroup(ctx context.Context, params *pb.GroupParams) (*pb.CommandOutput, bool, error) {
	var output strings.Builder
	changed := false

	// Check idempotency: group exists and members match
	if groupExists(params.Name) && sudoGroupMembersMatch(params.Name, params.Members) {
		output.WriteString(fmt.Sprintf("group %s already up to date\n", params.Name))
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   output.String(),
		}, false, nil
	}

	if !e.repairFilesystem(ctx) {
		return &pb.CommandOutput{
			ExitCode: 1,
			Stderr:   "filesystem is read-only and could not be remounted",
		}, false, fmt.Errorf("filesystem is read-only")
	}

	// Create group if it doesn't exist
	if !groupExists(params.Name) {
		var extraArgs []string
		if params.Gid > 0 {
			extraArgs = append(extraArgs, "-g", fmt.Sprintf("%d", params.Gid))
		}
		if params.SystemGroup {
			extraArgs = append(extraArgs, "-r")
		}

		if err := sysuser.GroupCreate(ctx, params.Name, extraArgs...); err != nil {
			return nil, false, fmt.Errorf("create group %s: %v", params.Name, err)
		}
		output.WriteString(fmt.Sprintf("created group: %s\n", params.Name))
		changed = true
	}

	// Add missing members
	for _, member := range params.Members {
		if !userExists(member) {
			output.WriteString(fmt.Sprintf("warning: user %q does not exist, skipping\n", member))
			continue
		}
		if !userInGroup(member, params.Name) {
			if err := addUserToGroup(ctx, member, params.Name); err != nil {
				output.WriteString(fmt.Sprintf("warning: failed to add user %s to group: %v\n", member, err))
			} else {
				output.WriteString(fmt.Sprintf("added user %s to group %s\n", member, params.Name))
				changed = true
			}
		}
	}

	// Remove members not in desired list
	currentMembers := getGroupMembers(params.Name)
	desiredSet := make(map[string]bool, len(params.Members))
	for _, m := range params.Members {
		desiredSet[m] = true
	}
	for _, member := range currentMembers {
		if !desiredSet[member] {
			if err := removeUserFromGroup(ctx, member, params.Name); err == nil {
				output.WriteString(fmt.Sprintf("removed user %s from group %s\n", member, params.Name))
				changed = true
			}
		}
	}

	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   output.String(),
	}, changed, nil
}

// removeGroup removes a group and all its members.
func (e *Executor) removeGroup(ctx context.Context, groupName string) (*pb.CommandOutput, bool, error) {
	var output strings.Builder

	// Never allow removal of the agent's own service group
	if groupName == "power-manage" {
		return &pb.CommandOutput{
			ExitCode: 1,
			Stderr:   "refusing to remove the power-manage service group\n",
		}, false, fmt.Errorf("cannot remove protected group: power-manage")
	}

	if !groupExists(groupName) {
		output.WriteString(fmt.Sprintf("group %s does not exist, nothing to remove\n", groupName))
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   output.String(),
		}, false, nil
	}

	if !e.repairFilesystem(ctx) {
		return &pb.CommandOutput{
			ExitCode: 1,
			Stderr:   "filesystem is read-only and could not be remounted",
		}, false, fmt.Errorf("filesystem is read-only")
	}

	// Remove all members from group
	members := getGroupMembers(groupName)
	for _, member := range members {
		if err := removeUserFromGroup(ctx, member, groupName); err == nil {
			output.WriteString(fmt.Sprintf("removed user %s from group %s\n", member, groupName))
		}
	}

	// Delete group
	if err := sysuser.GroupDelete(ctx, groupName); err != nil {
		return nil, false, fmt.Errorf("delete group %s: %v", groupName, err)
	}
	output.WriteString(fmt.Sprintf("deleted group: %s\n", groupName))

	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   output.String(),
	}, true, nil
}
