package executor

import (
	"fmt"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/go/verify"
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

// VerifyOSQuery verifies the CA signature binding an OSQuery (table OR raw_sql).
func (e *Executor) VerifyOSQuery(q *pb.OSQuery) error {
	if e.verifier == nil {
		return fmt.Errorf("no verifier configured; refusing unverified osquery")
	}
	canonical, err := verify.OSQueryCanonical(q)
	if err != nil {
		return err
	}
	return e.verifier.VerifyDomain(verify.OSQuerySignatureDomain, canonical, q.GetSignature())
}

// VerifyLogQuery verifies the CA signature binding a LogQuery.
func (e *Executor) VerifyLogQuery(q *pb.LogQuery) error {
	if e.verifier == nil {
		return fmt.Errorf("no verifier configured; refusing unverified log query")
	}
	canonical, err := verify.LogQueryCanonical(q)
	if err != nil {
		return err
	}
	return e.verifier.VerifyDomain(verify.LogQuerySignatureDomain, canonical, q.GetSignature())
}

// VerifyRevokeLuksDeviceKey verifies the CA signature binding a
// RevokeLuksDeviceKey before the destructive, irreversible slot-7 wipe.
func (e *Executor) VerifyRevokeLuksDeviceKey(m *pb.RevokeLuksDeviceKey) error {
	if e.verifier == nil {
		return fmt.Errorf("no verifier configured; refusing unverified LUKS revoke")
	}
	canonical, err := verify.RevokeLuksDeviceKeyCanonical(m)
	if err != nil {
		return err
	}
	return e.verifier.VerifyDomain(verify.LuksRevokeSignatureDomain, canonical, m.GetSignature())
}

// VerifyRequestInventory verifies the CA signature binding a server-originated
// RequestInventory. (Agent-initiated periodic collection never reaches this.)
func (e *Executor) VerifyRequestInventory(m *pb.RequestInventory) error {
	if e.verifier == nil {
		return fmt.Errorf("no verifier configured; refusing unverified inventory request")
	}
	canonical, err := verify.RequestInventoryCanonical(m)
	if err != nil {
		return err
	}
	return e.verifier.VerifyDomain(verify.InventorySignatureDomain, canonical, m.GetSignature())
}
