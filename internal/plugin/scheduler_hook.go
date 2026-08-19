package plugin

import (
	"encoding/json"

	"github.com/nguyenha935/manager-key-pro/internal/crypto"
	"github.com/nguyenha935/manager-key-pro/internal/scheduler"
)

// handleSchedulerPick applies per-key upstream account bindings (design §2.4).
// Only requests carrying an MKP key are handled; everything else falls through
// to the host scheduler so non-plugin traffic is untouched.
func handleSchedulerPick(payload []byte) ([]byte, error) {
	if app == nil {
		return okEnvelopeJSON(`{"Handled":false}`)
	}
	var req scheduler.PickRequest
	if errUnmarshal := json.Unmarshal(payload, &req); errUnmarshal != nil {
		return okEnvelopeJSON(`{"Handled":false}`)
	}
	plaintext := extractKey(req.Options.Headers, nil)
	if plaintext == "" {
		return okEnvelopeJSON(`{"Handled":false}`)
	}
	resp := scheduler.HandlePick(app.db, req, crypto.HashKey(plaintext))
	return okEnvelopeJSON(scheduler.MarshalPick(resp))
}
