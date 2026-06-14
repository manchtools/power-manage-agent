package executor

import (
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

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

// protoFieldName extracts the snake_case proto field name from the
// generated struct's `protobuf:"...,name=foo,..."` tag, or "" for the
// proto-internal fields (state/sizeCache/unknownFields have no tag).
func protoFieldName(f reflect.StructField) string {
	for _, part := range strings.Split(f.Tag.Get("protobuf"), ",") {
		if strings.HasPrefix(part, "name=") {
			return strings.TrimPrefix(part, "name=")
		}
	}
	return ""
}

// TestValidateRepositoryParams_SelfDiscoversEveryStringField is the
// self-discovering replacement for the stale hardcoded subset (finding
// 4). It reflection-walks every string / []string field of every repo
// proto, injects a newline-bearing value into exactly one field, and
// asserts the validator rejects it AND names that field. A newly-added
// proto field that forgets its newline guard makes this FAIL — the test
// fails CLOSED: a field is "must be guarded" unless it is consciously
// listed in `multiLineContent` with a justification.
func TestValidateRepositoryParams_SelfDiscoversEveryStringField(t *testing.T) {
	// Fields whose value is legitimately multi-line content written to a
	// file (not spliced into a config line or argv), so the newline guard
	// must NOT apply. NOT a fail-open allowlist: a new field is absent
	// here by default and therefore REQUIRED to carry the newline guard.
	multiLineContent := map[string]bool{
		"apt.gpg_key": true, // ASCII-armored key blob, written verbatim to a keyring file
	}

	managers := []struct {
		prefix string
		empty  func() proto.Message
		wrap   func(proto.Message) *pb.RepositoryParams
	}{
		{"apt", func() proto.Message { return &pb.AptRepository{} }, func(m proto.Message) *pb.RepositoryParams {
			return &pb.RepositoryParams{Name: "r", Apt: m.(*pb.AptRepository)}
		}},
		{"dnf", func() proto.Message { return &pb.DnfRepository{} }, func(m proto.Message) *pb.RepositoryParams {
			return &pb.RepositoryParams{Name: "r", Dnf: m.(*pb.DnfRepository)}
		}},
		{"pacman", func() proto.Message { return &pb.PacmanRepository{} }, func(m proto.Message) *pb.RepositoryParams {
			return &pb.RepositoryParams{Name: "r", Pacman: m.(*pb.PacmanRepository)}
		}},
		{"zypper", func() proto.Message { return &pb.ZypperRepository{} }, func(m proto.Message) *pb.RepositoryParams {
			return &pb.RepositoryParams{Name: "r", Zypper: m.(*pb.ZypperRepository)}
		}},
	}

	const payload = "x\nEvil: 1"
	covered, urlish := 0, 0
	for _, mgr := range managers {
		rt := reflect.TypeOf(mgr.empty()).Elem()
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			snake := protoFieldName(f)
			if snake == "" {
				continue
			}
			isString := f.Type.Kind() == reflect.String
			isStringSlice := f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.String
			if !isString && !isStringSlice {
				continue
			}
			key := mgr.prefix + "." + snake
			if multiLineContent[key] {
				continue
			}

			fresh := reflect.New(rt)
			fv := fresh.Elem().Field(i)
			if isString {
				fv.SetString(payload)
			} else {
				fv.Set(reflect.ValueOf([]string{payload}))
			}
			params := mgr.wrap(fresh.Interface().(proto.Message))

			err := validateRepositoryParams(params)
			if err == nil {
				t.Errorf("%s: newline-injected value accepted (field unguarded)", key)
				continue
			}
			if !strings.Contains(err.Error(), snake) {
				t.Errorf("%s: error should name the field %q; got: %v", key, snake, err)
			}
			covered++
			if l := strings.ToLower(snake); strings.Contains(l, "url") || strings.Contains(l, "server") || strings.Contains(l, "gpgkey") {
				urlish++
			}
		}
	}
	if covered == 0 {
		t.Fatal("self-discovering walk covered 0 fields — reflection is broken")
	}
	if urlish == 0 {
		t.Fatal("no URL-ish field (url/server/gpgkey) was exercised — guard/walk mismatch")
	}
}

// TestValidateRepositoryParams_RejectsNonHttpsBaseURL pins finding 3:
// dnf baseurl / zypper url / pacman server (where ROOT packages are
// fetched) must be https. Gpgcheck is set so the zero-integrity rule
// does not mask the scheme check.
func TestValidateRepositoryParams_RejectsNonHttpsBaseURL(t *testing.T) {
	reject := []*pb.RepositoryParams{
		{Name: "r", Dnf: &pb.DnfRepository{Baseurl: "http://m/r", Gpgcheck: true}},
		{Name: "r", Zypper: &pb.ZypperRepository{Url: "http://m/r", Gpgcheck: true}},
		{Name: "r", Pacman: &pb.PacmanRepository{Server: "http://m/r"}},
		{Name: "r", Dnf: &pb.DnfRepository{Baseurl: "ftp://x", Gpgcheck: true}},
		{Name: "r", Dnf: &pb.DnfRepository{Baseurl: "file:///etc", Gpgcheck: true}},
	}
	for i, p := range reject {
		if err := validateRepositoryParams(p); err == nil {
			t.Errorf("reject case %d: non-https base URL accepted", i)
		}
	}
	accept := []*pb.RepositoryParams{
		{Name: "r", Dnf: &pb.DnfRepository{Baseurl: "https://m/$releasever", Gpgcheck: true}},
		{Name: "r", Pacman: &pb.PacmanRepository{Server: "https://m/$arch", SigLevel: "Optional TrustAll"}},
	}
	for i, p := range accept {
		if err := validateRepositoryParams(p); err != nil {
			t.Errorf("accept case %d: https base URL rejected: %v", i, err)
		}
	}
}

// TestValidateRepositoryParams_RejectsBadGpgKeyRef pins finding 2:
// dnf/zypper Gpgkey passed to `rpm --import` must be https/file/abs-path
// — never a flag, plaintext http, or rpm's ext:: command transport.
func TestValidateRepositoryParams_RejectsBadGpgKeyRef(t *testing.T) {
	reject := []*pb.RepositoryParams{
		{Name: "r", Dnf: &pb.DnfRepository{Baseurl: "https://m/r", Gpgcheck: true, Gpgkey: "http://evil/key"}},
		{Name: "r", Dnf: &pb.DnfRepository{Baseurl: "https://m/r", Gpgcheck: true, Gpgkey: "-"}},
		{Name: "r", Dnf: &pb.DnfRepository{Baseurl: "https://m/r", Gpgcheck: true, Gpgkey: "--import=/etc/shadow"}},
		{Name: "r", Dnf: &pb.DnfRepository{Baseurl: "https://m/r", Gpgcheck: true, Gpgkey: "ext::sh -c id"}},
		{Name: "r", Zypper: &pb.ZypperRepository{Url: "https://m/r", Gpgcheck: true, Gpgkey: "http://evil/key"}},
	}
	for i, p := range reject {
		if err := validateRepositoryParams(p); err == nil {
			t.Errorf("reject case %d: bad gpg key ref accepted", i)
		}
	}
	accept := []*pb.RepositoryParams{
		{Name: "r", Dnf: &pb.DnfRepository{Baseurl: "https://m/r", Gpgcheck: true, Gpgkey: "https://m/key.asc"}},
		{Name: "r", Dnf: &pb.DnfRepository{Baseurl: "https://m/r", Gpgcheck: true, Gpgkey: "file:///etc/pki/rpm-gpg/KEY"}},
		{Name: "r", Zypper: &pb.ZypperRepository{Url: "https://m/r", Gpgcheck: true, Gpgkey: "/etc/pki/rpm-gpg/KEY"}},
	}
	for i, p := range accept {
		if err := validateRepositoryParams(p); err != nil {
			t.Errorf("accept case %d: good gpg key ref rejected: %v", i, err)
		}
	}
}

// TestValidateRepositoryParams_AllowsOperatorChoiceGpgcheck pins the
// deliberate decision (ADR 0012): gpgcheck is an OPERATOR CHOICE, not a
// hard gate. An https base URL with gpgcheck=false and no key is a
// legitimate (if less-verified) internal-mirror configuration and must
// NOT be rejected — mirroring the WS7 checksum_url posture (the https
// transport is still enforced; package-signature verification is the
// operator's call). This guards against a future contributor
// re-introducing a refusal that would break real operators.
func TestValidateRepositoryParams_AllowsOperatorChoiceGpgcheck(t *testing.T) {
	accept := []*pb.RepositoryParams{
		{Name: "r", Dnf: &pb.DnfRepository{Baseurl: "https://m/r", Gpgcheck: false}},                        // gpgcheck off, no key — operator choice
		{Name: "r", Dnf: &pb.DnfRepository{Baseurl: "https://m/r", Gpgcheck: true}},                         // gpgcheck on
		{Name: "r", Dnf: &pb.DnfRepository{Baseurl: "https://m/r", Gpgcheck: false, Gpgkey: "https://m/k"}}, // key supplied
		{Name: "r", Zypper: &pb.ZypperRepository{Url: "https://m/r", Gpgcheck: false}},
	}
	for i, p := range accept {
		if err := validateRepositoryParams(p); err != nil {
			t.Errorf("accept case %d: legitimate operator-choice config rejected: %v", i, err)
		}
	}
}
