package executor

import (
	"fmt"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/verify"
)

// Stream-RPC signature verification (WS4). The four root stream-RPCs
// (osquery, log query, LUKS revoke, server-originated inventory) are CA-signed
// at the control server and must be verified by the agent before any root work.
// Each accessor verifies the message's canonical bytes under that surface's
// disjoint signing domain using the SAME configured verifier as actions.
//
// Fail-closed: a nil verifier returns an error rather than passing the message
// through unverified — identical to VerifyEnvelope for actions. In production
// the agent always carries a verifier (the CA cert is required at startup; a
// missing cert is fatal), so a nil verifier means a wiring bug or a test that
// forgot one, and either way must NOT become a silent "run everything unsigned"
// hole. The handler treats any error here as a hard refusal and never runs the
// request.

// enforceTargetDevice turns signature verification into an authorization step:
// the signed target_device_id must name THIS device. The CA signature proves a
// message is authentic, NOT that this device is its intended recipient — so a
// compromised gateway/relay can take one device's validly-signed message and
// forward it to another device that trusts the same CA. Binding + checking the
// target closes that cross-device replay (PMSEC-001). It is the same guarantee
// SignedActionEnvelope.target_device_id gives actions (see VerifyEnvelope),
// extended to the four non-action stream-RPC surfaces.
//
// Fail closed: refuse if we do not know our own device id, or the message
// targets a different (or empty) device. The message string contains "target
// device" — asserted by execute_verified_envelope_test.go.
func (e *Executor) enforceTargetDevice(target string) error {
	expected := e.getDeviceID()
	if expected == "" {
		return fmt.Errorf("refusing: agent device id not configured")
	}
	if target != expected {
		return fmt.Errorf("refusing: signed target device %q is not this device %q", target, expected)
	}
	return nil
}

// VerifyOSQuery verifies the CA signature binding an OSQuery (table OR raw_sql)
// and that it is targeted at this device.
func (e *Executor) VerifyOSQuery(q *pb.OSQuery) error {
	if e.verifier == nil {
		return fmt.Errorf("no verifier configured; refusing unverified osquery")
	}
	canonical, err := verify.OSQueryCanonical(q)
	if err != nil {
		return err
	}
	if err := e.verifier.VerifyDomain(verify.OSQuerySignatureDomain, canonical, q.GetSignature()); err != nil {
		return err
	}
	return e.enforceTargetDevice(q.GetTargetDeviceId())
}

// VerifyLogQuery verifies the CA signature binding a LogQuery and that it is
// targeted at this device.
func (e *Executor) VerifyLogQuery(q *pb.LogQuery) error {
	if e.verifier == nil {
		return fmt.Errorf("no verifier configured; refusing unverified log query")
	}
	canonical, err := verify.LogQueryCanonical(q)
	if err != nil {
		return err
	}
	if err := e.verifier.VerifyDomain(verify.LogQuerySignatureDomain, canonical, q.GetSignature()); err != nil {
		return err
	}
	return e.enforceTargetDevice(q.GetTargetDeviceId())
}

// VerifyRevokeLuksDeviceKey verifies the CA signature binding a
// RevokeLuksDeviceKey and that it is targeted at this device, before the
// destructive, irreversible slot-7 wipe.
func (e *Executor) VerifyRevokeLuksDeviceKey(m *pb.RevokeLuksDeviceKey) error {
	if e.verifier == nil {
		return fmt.Errorf("no verifier configured; refusing unverified LUKS revoke")
	}
	canonical, err := verify.RevokeLuksDeviceKeyCanonical(m)
	if err != nil {
		return err
	}
	if err := e.verifier.VerifyDomain(verify.LuksRevokeSignatureDomain, canonical, m.GetSignature()); err != nil {
		return err
	}
	return e.enforceTargetDevice(m.GetTargetDeviceId())
}

// VerifyRequestInventory verifies the CA signature binding a server-originated
// RequestInventory and that it is targeted at this device. (Agent-initiated
// periodic collection never reaches this.)
func (e *Executor) VerifyRequestInventory(m *pb.RequestInventory) error {
	if e.verifier == nil {
		return fmt.Errorf("no verifier configured; refusing unverified inventory request")
	}
	canonical, err := verify.RequestInventoryCanonical(m)
	if err != nil {
		return err
	}
	if err := e.verifier.VerifyDomain(verify.InventorySignatureDomain, canonical, m.GetSignature()); err != nil {
		return err
	}
	return e.enforceTargetDevice(m.GetTargetDeviceId())
}
