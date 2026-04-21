package executor

import (
	"strings"
	"testing"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// TestValidateRepositoryParams_AcceptsRealistic pins the expected
// shapes of legitimate repository configurations — regressions in
// the validator grammar must not reject these.
func TestValidateRepositoryParams_AcceptsRealistic(t *testing.T) {
	cases := map[string]*pb.RepositoryParams{
		"apt": {
			Apt: &pb.AptRepository{
				Url:          "https://apt.example.com/debian",
				Distribution: "bookworm",
				Components:   []string{"main", "contrib", "non-free-firmware"},
				Arch:         "amd64,arm64",
				GpgKeyUrl:    "https://apt.example.com/signing.asc",
			},
		},
		"dnf": {
			Dnf: &pb.DnfRepository{
				Baseurl:     "https://dnf.example.com/fedora/$releasever",
				Description: "Example DNF repo",
				Gpgkey:      "https://dnf.example.com/key.asc",
				Gpgcheck:    true,
			},
		},
		"pacman-optional-trustall": {
			Pacman: &pb.PacmanRepository{
				Server:   "https://arch.example.com/os/$arch",
				SigLevel: "Optional TrustAll",
			},
		},
		"zypper": {
			Zypper: &pb.ZypperRepository{
				Url:         "https://zypper.example.com/15.5",
				Description: "Example Zypper repo",
				Gpgkey:      "https://zypper.example.com/key.asc",
				Type:        "rpm-md",
			},
		},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			if err := validateRepositoryParams(p); err != nil {
				t.Fatalf("legitimate config rejected: %v", err)
			}
		})
	}
}

// TestValidateRepositoryParams_RejectsInjection is the regression:
// every repo string field must refuse newline injection and the
// enum-like fields must reject out-of-grammar values. A malformed
// signed action must NOT be able to smuggle extra directives into
// apt/dnf/pacman/zypper config.
func TestValidateRepositoryParams_RejectsInjection(t *testing.T) {
	cases := map[string]*pb.RepositoryParams{
		"apt distribution newline": {
			Apt: &pb.AptRepository{Distribution: "bookworm\nEvil: yes"},
		},
		"apt component newline": {
			Apt: &pb.AptRepository{Components: []string{"main", "contrib\nEvil: 1"}},
		},
		"apt component shape": {
			Apt: &pb.AptRepository{Components: []string{"main", "non-free evil"}},
		},
		"apt arch newline": {
			Apt: &pb.AptRepository{Arch: "amd64\n"},
		},
		"apt arch shape": {
			Apt: &pb.AptRepository{Arch: "amd64 arm64"}, // space not allowed
		},
		"apt gpg_key_url newline": {
			Apt: &pb.AptRepository{GpgKeyUrl: "https://a\nhttps://b"},
		},
		"dnf gpgkey newline": {
			Dnf: &pb.DnfRepository{Gpgkey: "https://a\nhttps://b"},
		},
		"pacman siglevel newline": {
			Pacman: &pb.PacmanRepository{SigLevel: "Required\nInjected=1"},
		},
		"pacman siglevel shape": {
			Pacman: &pb.PacmanRepository{SigLevel: "Required! TrustAll"},
		},
		"zypper type newline": {
			Zypper: &pb.ZypperRepository{Type: "rpm-md\nEvil: 1"},
		},
		"zypper type shape": {
			Zypper: &pb.ZypperRepository{Type: "rpm md"},
		},
		"zypper gpgkey newline": {
			Zypper: &pb.ZypperRepository{Gpgkey: "https://a\nhttps://b"},
		},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			err := validateRepositoryParams(p)
			if err == nil {
				t.Fatalf("expected rejection, got nil")
			}
			if !strings.Contains(err.Error(), "repository") {
				t.Errorf("error should name the repository field; got: %v", err)
			}
		})
	}
}
