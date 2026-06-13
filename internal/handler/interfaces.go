package handler

import sdk "github.com/manchtools/power-manage/sdk/go"

// Compile-time assertions that *Handler satisfies every optional SDK stream
// handler interface it is meant to serve. The SDK dispatch loop selects these
// via runtime type assertion (handler.(LuksHandler) etc.), so a signature drift
// would otherwise SILENTLY disable a whole RPC (e.g. LUKS revocation or
// server-requested inventory would just stop being handled) with no build or
// test failure. Pinning them here turns any such drift into a compile error.
var (
	_ sdk.StreamHandler    = (*Handler)(nil)
	_ sdk.LuksHandler      = (*Handler)(nil)
	_ sdk.LogQueryHandler  = (*Handler)(nil)
	_ sdk.InventoryHandler = (*Handler)(nil)
)
