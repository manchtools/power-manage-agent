package executor

import (
	"context"
	"fmt"
	"strings"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// executeGroup manages Linux groups and their members.
func (e *Executor) executeGroup(ctx context.Context, params *pb.GroupParams, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("group params required")
	}
	if !isValidUsername(params.Name) {
		return nil, false, fmt.Errorf("invalid group name: %q", params.Name)
	}

	for _, m := range params.Members {
		if !isValidUsername(m) {
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

		if grpOut, err := groupAdd(ctx, params.Name, extraArgs...); err != nil {
			errMsg := "failed to create group"
			if grpOut != nil && grpOut.Stderr != "" {
				errMsg = strings.TrimSpace(grpOut.Stderr)
			}
			return nil, false, fmt.Errorf("create group %s: %s", params.Name, errMsg)
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
			if addOut, err := addUserToGroup(ctx, member, params.Name); err != nil {
				errMsg := "failed to add user to group"
				if addOut != nil && addOut.Stderr != "" {
					errMsg = strings.TrimSpace(addOut.Stderr)
				}
				output.WriteString(fmt.Sprintf("warning: %s for user %s: %s\n", errMsg, member, err))
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
			if _, err := removeUserFromGroup(ctx, member, params.Name); err == nil {
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
		if _, err := removeUserFromGroup(ctx, member, groupName); err == nil {
			output.WriteString(fmt.Sprintf("removed user %s from group %s\n", member, groupName))
		}
	}

	// Delete group
	if delOut, err := groupDel(ctx, groupName); err != nil {
		errMsg := "failed to delete group"
		if delOut != nil && delOut.Stderr != "" {
			errMsg = strings.TrimSpace(delOut.Stderr)
		}
		return nil, false, fmt.Errorf("delete group %s: %s", groupName, errMsg)
	}
	output.WriteString(fmt.Sprintf("deleted group: %s\n", groupName))

	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   output.String(),
	}, true, nil
}
