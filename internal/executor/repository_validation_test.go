package executor

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/pkg"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
	"github.com/manchtools/power-manage-sdk/sys/repo"
)

// Repository field validation is now owned by the SDK's repo.Manager.Validate;
// executeRepository runs it (on the agent's repositoryFields mapping) as its
// pre-flight gate. These tests drive that exact path: they prove the agent's
// proto->repo mapping reaches repo.Validate and that injection is rejected, and
// pin the agent-level decisions the SDK can't (ADR 0012 operator-choice gpgcheck;
// which fields are validated at this gate vs. later in downloadAptKey).

// validateRepoViaSDK builds the SDK repo.Manager for whichever backend the params
// configure and validates the agent's field mapping through it — the path
// executeRepository uses. The runner is a fake (Validate runs no commands).
func validateRepoViaSDK(t *testing.T, p *pb.RepositoryParams) error {
	t.Helper()
	var backend pkg.Backend
	switch {
	case p.Apt != nil:
		backend = pkg.Apt
	case p.Dnf != nil:
		backend = pkg.Dnf
	case p.Pacman != nil:
		backend = pkg.Pacman
	case p.Zypper != nil:
		backend = pkg.Zypper
	default:
		t.Fatal("test params configure no backend")
	}
	mgr, err := repo.New(backend, exectest.New(sysexec.Direct))
	require.NoError(t, err)
	e := &Executor{pkgBackend: backend}
	return mgr.Validate(e.repositoryFields(p))
}

// TestRepository_AcceptsRealistic pins that legitimate configurations pass the
// SDK validation through the agent's mapping — a regression in the mapping or a
// grammar over-tightening must not reject these.
func TestRepository_AcceptsRealistic(t *testing.T) {
	cases := map[string]*pb.RepositoryParams{
		"apt": {Name: "r", Apt: &pb.AptRepository{
			Url: "https://apt.example.com/debian", Distribution: "bookworm",
			Components: []string{"main", "contrib", "non-free-firmware"}, Arch: "amd64,arm64",
		}},
		"dnf": {Name: "r", Dnf: &pb.DnfRepository{
			Baseurl: "https://dnf.example.com/fedora/$releasever", Description: "Example DNF repo",
			Gpgkey: "https://dnf.example.com/key.asc", Gpgcheck: true,
		}},
		"pacman": {Name: "r", Pacman: &pb.PacmanRepository{
			Server: "https://arch.example.com/os/$arch", SigLevel: "Optional TrustAll",
		}},
		"zypper": {Name: "r", Zypper: &pb.ZypperRepository{
			Url: "https://zypper.example.com/15.5", Description: "Example Zypper repo",
			Gpgkey: "https://zypper.example.com/key.asc", Type: "rpm-md",
		}},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			if err := validateRepoViaSDK(t, p); err != nil {
				t.Fatalf("legitimate config rejected: %v", err)
			}
		})
	}
}

// TestRepository_RejectsBadBaseURLAndGpgKey pins the load-bearing security
// properties through the delegation: dnf/zypper/pacman base URLs where ROOT
// packages are fetched must be https, and a dnf/zypper gpgkey ref passed to
// `rpm --import` must be a safe https/file/abs-path (never a flag, plaintext
// http, or rpm's ext:: command transport). A future swap of the SDK call must
// not silently drop these.
func TestRepository_RejectsBadBaseURLAndGpgKey(t *testing.T) {
	reject := []*pb.RepositoryParams{
		{Name: "r", Dnf: &pb.DnfRepository{Baseurl: "http://m/r", Gpgcheck: true}},
		{Name: "r", Zypper: &pb.ZypperRepository{Url: "http://m/r", Gpgcheck: true}},
		{Name: "r", Pacman: &pb.PacmanRepository{Server: "http://m/r"}},
		{Name: "r", Dnf: &pb.DnfRepository{Baseurl: "ftp://x", Gpgcheck: true}},
		{Name: "r", Dnf: &pb.DnfRepository{Baseurl: "https://m/r", Gpgcheck: true, Gpgkey: "http://evil/key"}},
		{Name: "r", Dnf: &pb.DnfRepository{Baseurl: "https://m/r", Gpgcheck: true, Gpgkey: "ext::sh -c id"}},
		{Name: "r", Dnf: &pb.DnfRepository{Baseurl: "https://m/r", Gpgcheck: true, Gpgkey: "--import=/etc/shadow"}},
	}
	for i, p := range reject {
		if err := validateRepoViaSDK(t, p); err == nil {
			t.Errorf("reject case %d accepted a non-https base URL or unsafe gpg key ref", i)
		}
	}
}

// TestRepository_AllowsOperatorChoiceGpgcheck pins ADR 0012 through the
// delegation: gpgcheck is an OPERATOR CHOICE, not a hard gate. An https base URL
// with gpgcheck=false (and no key) is a legitimate internal-mirror config and
// must NOT be rejected. Guards against a future contributor (or SDK change)
// re-introducing a refusal that would break real operators.
func TestRepository_AllowsOperatorChoiceGpgcheck(t *testing.T) {
	accept := []*pb.RepositoryParams{
		{Name: "r", Dnf: &pb.DnfRepository{Baseurl: "https://m/r", Gpgcheck: false}},
		{Name: "r", Dnf: &pb.DnfRepository{Baseurl: "https://m/r", Gpgcheck: false, Gpgkey: "https://m/k"}},
		{Name: "r", Zypper: &pb.ZypperRepository{Url: "https://m/r", Gpgcheck: false}},
	}
	for i, p := range accept {
		if err := validateRepoViaSDK(t, p); err != nil {
			t.Errorf("accept case %d: legitimate operator-choice config rejected: %v", i, err)
		}
	}
}

// protoFieldName extracts the snake_case proto field name from the generated
// struct's `protobuf:"...,name=foo,..."` tag, or "" for proto-internal fields.
func protoFieldName(f reflect.StructField) string {
	for _, part := range strings.Split(f.Tag.Get("protobuf"), ",") {
		if strings.HasPrefix(part, "name=") {
			return strings.TrimPrefix(part, "name=")
		}
	}
	return ""
}

// TestRepository_SelfDiscoversEveryStringField is the self-discovering guard
// (finding 4): reflection-walk every string / []string field of every repo
// proto, inject a control-char value into exactly that field on an otherwise
// VALID base config (so the SDK's required-field checks don't mask it), and
// assert the agent's mapping + repo.Validate reject it. A newly-added proto
// field that the agent forgets to map (repositoryFields) or that repo.Validate
// forgets to guard makes this FAIL — it fails CLOSED: a field is "must be
// guarded" unless consciously excluded with a justification.
func TestRepository_SelfDiscoversEveryStringField(t *testing.T) {
	// Excluded: fields NOT validated at the repo.Validate gate.
	//   - apt.gpg_key:     ASCII-armored key blob written verbatim to a keyring
	//                      file (legitimate multi-line content, not a config line).
	//   - apt.gpg_key_url: the agent's OWN field (resolved by downloadAptKey, which
	//                      validates it via sdk.ValidateHTTPSURL — see
	//                      TestDownloadAptKey_RejectsNonHTTPS); it is not part of the
	//                      repositoryFields mapping that reaches repo.Validate.
	// NOT a fail-open allowlist: a new field is absent here by default and
	// therefore REQUIRED to be mapped + guarded.
	excluded := map[string]bool{
		"apt.gpg_key":     true,
		"apt.gpg_key_url": true,
	}

	managers := []struct {
		prefix string
		base   func() proto.Message // a VALID config (required fields set)
		wrap   func(proto.Message) *pb.RepositoryParams
	}{
		{"apt",
			func() proto.Message {
				return &pb.AptRepository{Url: "https://m/d", Distribution: "stable", Components: []string{"main"}, Arch: "amd64"}
			},
			func(m proto.Message) *pb.RepositoryParams {
				return &pb.RepositoryParams{Name: "r", Apt: m.(*pb.AptRepository)}
			}},
		{"dnf",
			func() proto.Message { return &pb.DnfRepository{Baseurl: "https://m/r"} },
			func(m proto.Message) *pb.RepositoryParams {
				return &pb.RepositoryParams{Name: "r", Dnf: m.(*pb.DnfRepository)}
			}},
		{"pacman",
			func() proto.Message { return &pb.PacmanRepository{Server: "https://m/x"} },
			func(m proto.Message) *pb.RepositoryParams {
				return &pb.RepositoryParams{Name: "r", Pacman: m.(*pb.PacmanRepository)}
			}},
		{"zypper",
			func() proto.Message { return &pb.ZypperRepository{Url: "https://m/r"} },
			func(m proto.Message) *pb.RepositoryParams {
				return &pb.RepositoryParams{Name: "r", Zypper: m.(*pb.ZypperRepository)}
			}},
	}

	const payload = "x\nEvil: 1"
	covered, urlish := 0, 0
	for _, mgr := range managers {
		rt := reflect.TypeOf(mgr.base()).Elem()
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
			if excluded[key] {
				continue
			}

			// Start from a VALID base, then poison exactly the field under test.
			fresh := mgr.base()
			fv := reflect.ValueOf(fresh).Elem().Field(i)
			if isString {
				fv.SetString(payload)
			} else {
				fv.Set(reflect.ValueOf([]string{payload}))
			}

			if err := validateRepoViaSDK(t, mgr.wrap(fresh)); err == nil {
				t.Errorf("%s: control-char value accepted (field unmapped or unguarded)", key)
				continue
			}
			covered++
			if strings.Contains(snake, "url") || strings.Contains(snake, "server") ||
				strings.Contains(snake, "gpgkey") || strings.Contains(snake, "baseurl") {
				urlish++
			}
		}
	}
	if covered == 0 {
		t.Fatal("self-discovering walk covered 0 fields — reflection is broken")
	}
	if urlish == 0 {
		t.Fatal("no URL-ish field (url/server/baseurl/gpgkey) was exercised — mapping/walk mismatch")
	}
}
