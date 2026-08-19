// Package scheduler implements the per-key upstream credential binding
// (design §2.4): each key may pin CPA auth accounts with a share percentage;
// scheduler.pick filters the host's candidates to the bound accounts and picks
// one weighted by share_percent. Requests without an MKP key are never handled
// (Handled=false) so non-plugin traffic is untouched.
package scheduler

import (
	"database/sql"
	"encoding/json"
	"log"
	"strings"
	"sync"

	"github.com/nguyenha935/manager-key-pro/internal/store"
)

// PickRequest mirrors pluginapi.SchedulerPickRequest (fields we use).
type PickRequest struct {
	Provider   string              `json:"Provider"`
	Providers  []string            `json:"Providers"`
	Model      string              `json:"Model"`
	Stream     bool                `json:"Stream"`
	Options    PickOptions         `json:"Options"`
	Candidates []AuthCandidate     `json:"Candidates"`
}

type PickOptions struct {
	Headers  map[string][]string `json:"Headers,omitempty"`
	Metadata map[string]any      `json:"Metadata,omitempty"`
}

// AuthCandidate mirrors pluginapi.SchedulerAuthCandidate.
type AuthCandidate struct {
	ID         string            `json:"ID"`
	Provider   string            `json:"Provider"`
	Priority   int               `json:"Priority"`
	Status     string            `json:"Status"`
	Attributes map[string]string `json:"Attributes"`
	Metadata   map[string]any    `json:"Metadata"`
}

// PickResponse mirrors pluginapi.SchedulerPickResponse.
type PickResponse struct {
	AuthID          string `json:"AuthID,omitempty"`
	DelegateBuiltin string `json:"DelegateBuiltin,omitempty"`
	Handled         bool   `json:"Handled"`
}

// Binding mirrors one key_account_bindings row.
type Binding struct {
	ID            int64  `json:"id"`
	KeyID         string `json:"key_id"`
	AccountRef    string `json:"account_ref"`
	AccountType   string `json:"account_type"`
	SharePercent  int64  `json:"share_percent"`
	Priority      int64  `json:"priority"`
	Enabled       bool   `json:"enabled"`
}

// ListBindings returns all bindings of a key (enabled first).
func ListBindings(db *store.DB, keyID string) ([]Binding, error) {
	rows, err := db.SQL().Query(`
		SELECT id, key_id, account_ref, COALESCE(account_type,''), share_percent, priority, enabled
		FROM key_account_bindings WHERE key_id = ?
		ORDER BY enabled DESC, priority ASC, id ASC`, keyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Binding
	for rows.Next() {
		var b Binding
		var enabled int
		if errScan := rows.Scan(&b.ID, &b.KeyID, &b.AccountRef, &b.AccountType,
			&b.SharePercent, &b.Priority, &enabled); errScan != nil {
			return nil, errScan
		}
		b.Enabled = enabled != 0
		out = append(out, b)
	}
	if out == nil {
		out = []Binding{}
	}
	return out, nil
}

// SetBindings replaces the binding set of one key in a transaction.
func SetBindings(db *store.DB, keyID string, bindings []Binding) error {
	if _, errUser := db.Keys().ByID(keyID); errUser != nil {
		return errUser
	}
	total := int64(0)
	for _, b := range bindings {
		if b.SharePercent < 0 || b.SharePercent > 100 {
			return errBadShare
		}
		if strings.TrimSpace(b.AccountRef) == "" {
			return errEmptyRef
		}
		total += b.SharePercent
	}
	if len(bindings) > 0 && total > 100 {
		return errShareOverflow
	}
	return db.Tx(func(tx *sql.Tx) error {
		if _, errDel := tx.Exec(`DELETE FROM key_account_bindings WHERE key_id = ?`, keyID); errDel != nil {
			return errDel
		}
		for _, b := range bindings {
			enabled := 0
			if b.Enabled {
				enabled = 1
			}
			share := b.SharePercent
			if share <= 0 {
				share = 100
			}
			if _, errIns := tx.Exec(`
				INSERT INTO key_account_bindings (key_id, account_ref, account_type, share_percent, priority, enabled, created_at)
				VALUES (?, ?, ?, ?, ?, ?, ?)`,
				keyID, strings.TrimSpace(b.AccountRef), b.AccountType, share, b.Priority, enabled, store.Now()); errIns != nil {
				return errIns
			}
		}
		return nil
	})
}

type bindingError string

func (e bindingError) Error() string { return string(e) }

const (
	errBadShare     = bindingError("share_percent must be 0-100")
	errEmptyRef     = bindingError("account_ref is required")
	errShareOverflow = bindingError("total share_percent exceeds 100")
)

var _ = log.Printf

// pickState keeps a weighted round-robin cursor per key so consecutive requests
// spread across accounts according to share_percent.
var (
	mu     sync.Mutex
	cursors = map[string]int{}
)

// HandlePick resolves the MKP key from the request headers, applies its
// bindings to the candidate list, and returns a weighted pick. When the key has
// no bindings or the headers carry no MKP key, it declines (Handled=false) so
// the host scheduler stays in charge — non-MKP traffic is never touched.
func HandlePick(db *store.DB, req PickRequest, keyHash string) PickResponse {
	if keyHash == "" {
		return PickResponse{Handled: false}
	}
	key, errKey := db.Keys().ByHash(keyHash)
	if errKey != nil {
		return PickResponse{Handled: false}
	}
	bindings, errList := ListBindings(db, key.ID)
	if errList != nil || len(bindings) == 0 {
		return PickResponse{Handled: false}
	}

	// Map candidate IDs for this provider. Candidate IDs arrive as the auth file
	// ID; AuthIDs look like "provider:kind:id" — match either tail or exact.
	eligible := make([]struct {
		candidate AuthCandidate
		share     int64
	}, 0, len(bindings))
	for _, cand := range req.Candidates {
		for _, b := range bindings {
			if !b.Enabled {
				continue
			}
			if candidateMatches(cand.ID, b.AccountRef, req.Provider) {
				share := b.SharePercent
				if share <= 0 {
					share = 1
				}
				eligible = append(eligible, struct {
					candidate AuthCandidate
					share     int64
				}{cand, share})
				break
			}
		}
	}
	if len(eligible) == 0 {
		// No bound account is currently a candidate: delegate rather than fail.
		return PickResponse{DelegateBuiltin: "round-robin", Handled: true}
	}
	if len(eligible) == 1 {
		return PickResponse{AuthID: eligible[0].candidate.ID, Handled: true}
	}

	// Weighted round-robin: pick by cumulative share using a rotating cursor.
	mu.Lock()
	cursor := cursors[key.ID]
	cursors[key.ID] = cursor + 1
	mu.Unlock()
	_ = cursor

	var total int64
	for _, e := range eligible {
		total += e.share
	}
	slot := int64(cursor) % total
	var acc int64
	for _, e := range eligible {
		acc += e.share
		if slot < acc {
			return PickResponse{AuthID: e.candidate.ID, Handled: true}
		}
	}
	return PickResponse{AuthID: eligible[0].candidate.ID, Handled: true}
}

// candidateMatches reports whether a host candidate matches a stored binding
// reference. Bindings store either the bare auth file ID or the full
// "provider:kind:id" AuthID; both forms must match.
func candidateMatches(candidateID, accountRef, provider string) bool {
	candidateID = strings.TrimSpace(candidateID)
	accountRef = strings.TrimSpace(accountRef)
	if candidateID == "" || accountRef == "" {
		return false
	}
	if candidateID == accountRef {
		return true
	}
	// accountRef may be "provider:kind:id" — its tail must equal candidateID.
	if parts := strings.Split(accountRef, ":"); len(parts) == 3 {
		if parts[2] == candidateID && strings.EqualFold(parts[0], provider) {
			return true
		}
	}
	// Or the reverse: candidate is the full form, ref is the tail.
	if parts := strings.Split(candidateID, ":"); len(parts) == 3 {
		if parts[2] == accountRef {
			return true
		}
	}
	return false
}

// MarshalPick is a helper for the plugin RPC envelope.
func MarshalPick(resp PickResponse) string {
	raw, err := json.Marshal(resp)
	if err != nil {
		return `{"Handled":false}`
	}
	return string(raw)
}
