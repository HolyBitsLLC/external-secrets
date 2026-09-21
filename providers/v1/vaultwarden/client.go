//go:build vaultwarden || all_providers

/*
Copyright © The ESO Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package vaultwarden

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/providers/v1/vaultwarden/internal/crypto"
)

// vaultwardenCipher represents a vault item returned from /api/ciphers or /api/sync.
type vaultwardenCipher struct {
	ID             string        `json:"id"`
	Type           int           `json:"type"`  // 1=Login, 2=SecureNote
	Name           string        `json:"name"`  // EncString
	Notes          string        `json:"notes"` // EncString (may be empty)
	Login          *cipherLogin  `json:"login"`
	Fields         []cipherField `json:"fields"`
	DeletedDate    interface{}   `json:"deletedDate"`
	OrganizationID interface{}   `json:"organizationId"` // nil=personal, string UUID=org
	// CollectionIDs are the organization collections this item belongs to.
	// Null/absent for personal items.
	CollectionIDs []string `json:"collectionIds"`
}

type cipherLogin struct {
	Password string `json:"password"` // EncString
	Username string `json:"username"` // EncString
}

type cipherField struct {
	Name  string `json:"name"`  // EncString
	Value string `json:"value"` // EncString
	Type  int    `json:"type"`  // 0=text
}

type ciphersListResponse struct {
	Data   []vaultwardenCipher `json:"data"`
	Object string              `json:"object"`
}

// syncResponse is the relevant subset of GET /api/sync: the cipher slice plus
// the collections the user can access, which is what lets a collection name be
// resolved to a UUID without a second round trip.
type syncResponse struct {
	Ciphers     []vaultwardenCipher `json:"ciphers"`
	Collections []collectionEntry   `json:"collections"`
}

// cipherOrgID extracts a cipher's organizationId as a string. The
// Vaultwarden API returns either null or a UUID string; we normalize.
func cipherOrgID(c vaultwardenCipher) string {
	if c.OrganizationID == nil {
		return ""
	}
	if s, ok := c.OrganizationID.(string); ok {
		return s
	}
	return ""
}

// filterCiphersByScope keeps only Login + SecureNote ciphers in the
// configured scope. orgID == "" means personal-only (org ciphers are
// dropped). orgID != "" means only that org's ciphers (personal items
// are dropped). Deleted ciphers are always dropped.
func filterCiphersByScope(ciphers []vaultwardenCipher, orgID string) []vaultwardenCipher {
	out := make([]vaultwardenCipher, 0, len(ciphers))
	for _, c := range ciphers {
		if c.DeletedDate != nil {
			continue
		}
		if c.Type != 1 && c.Type != 2 {
			continue
		}
		cOrg := cipherOrgID(c)
		if orgID == "" {
			if cOrg != "" {
				continue
			}
		} else {
			if cOrg != orgID {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

// cipherCreateBody is the JSON body for POST /api/ciphers and PUT /api/ciphers/{id}.
type cipherCreateBody struct {
	Type           int            `json:"type"`
	Name           string         `json:"name"`
	Notes          string         `json:"notes"`
	SecureNote     *secureNoteObj `json:"secureNote,omitempty"`
	FolderID       interface{}    `json:"folderId"`
	OrganizationID interface{}    `json:"organizationId"`
}

type secureNoteObj struct {
	Type int `json:"type"` // 0
}

// cachedToken holds a short-lived access token and symmetric key material
// so we don't re-authenticate on every API call within the same reconciliation.
type cachedToken struct {
	accessToken string
	symEncKey   []byte
	symMacKey   []byte
	expiresAt   time.Time
	// Org keys, populated only when the SecretStore configures an
	// organizationId or organizationName. orgID is the resolved UUID.
	orgID     string
	orgEncKey []byte
	orgMacKey []byte
	// rsaPriv is held briefly while decrypting org keys. nil for
	// personal-vault scope.
	rsaPriv *rsa.PrivateKey
}

// keysFor returns the encryption + MAC keys to use for the given cipher
// under the current scope. Because filterCiphersByScope guarantees a
// single scope is visible per cachedToken, keysFor effectively returns
// the personal keys when no org is configured and the org keys
// otherwise. The cipher's organizationId is used as a tie-break only
// if a future change relaxes the scope filter.
func (t *cachedToken) keysFor(c vaultwardenCipher) (enc, mac []byte) {
	if t.orgID != "" && cipherOrgID(c) == t.orgID {
		return t.orgEncKey, t.orgMacKey
	}
	return t.symEncKey, t.symMacKey
}

// invalidate zeros all key material in place and clears the cached
// strings. Called on TTL expiry, on auth errors (401/403), and on Close.
func (t *cachedToken) invalidate() {
	t.accessToken = ""
	zeroBytes(t.symEncKey)
	zeroBytes(t.symMacKey)
	zeroBytes(t.orgEncKey)
	zeroBytes(t.orgMacKey)
	t.symEncKey = nil
	t.symMacKey = nil
	t.orgEncKey = nil
	t.orgMacKey = nil
	t.orgID = ""
	t.rsaPriv = nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Client implements esv1.SecretsClient for Vaultwarden.
type Client struct {
	httpClient *http.Client
	provider   *esv1.VaultwardenProvider
	crClient   client.Client
	namespace  string
	store      esv1.GenericStore

	mu    sync.Mutex
	cache *cachedToken

	// secretCache holds resolved secret values. It is nil unless the store sets
	// spec.provider.vaultwarden.cache. Guarded internally by the LRU; the
	// cached-token mutex above is unrelated.
	secretCache *lru.LRU[string, []byte]
}

var _ esv1.SecretsClient = &Client{}

// bearerToken returns the Authorization header value for a given access token.
const bearerPrefix = "Bearer "

// Close is a no-op: the HTTP client is reusable and has no per-session state.
//
// It MUST stay a no-op. ESO's client manager calls Close on every client it
// handed out at the end of each reconcile (secretstore.Manager.Close), but the
// provider keeps this same Client in its provider-level cache across reconciles
// so the value cache survives. Tearing anything down here would silently defeat
// that cache on every reconcile.
func (c *Client) Close(_ context.Context) error {
	return nil
}

// Validate checks whether the client can authenticate and list ciphers.
// ClusterSecretStore cannot be validated (returns Unknown).
func (c *Client) Validate() (esv1.ValidationResult, error) {
	if c.store.GetObjectKind().GroupVersionKind().Kind == esv1.ClusterSecretStoreKind {
		return esv1.ValidationResultUnknown, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// Use getSymKey so we benefit from the token cache.
	accessToken, _, _, err := c.getSymKey(ctx)
	if err != nil {
		return esv1.ValidationResultError, fmt.Errorf("vaultwarden: validate: %w", err)
	}
	if _, err := c.listCiphersWithToken(ctx, accessToken); err != nil {
		return esv1.ValidationResultError, fmt.Errorf("vaultwarden: validate list: %w", err)
	}
	return esv1.ValidationResultReady, nil
}

// GetSecret returns a single secret value by cipher name (ref.Key).
// If ref.Property is set it looks up a named custom field; otherwise it returns
// the decrypted notes (SecureNote) or password (Login).
//
// When the store enables spec.provider.vaultwarden.cache, the resolved value is
// cached for the configured TTL, keyed by (item, kind, property) — see cache.go
// for why the store identity and scope are structurally implicit in that key.
func (c *Client) GetSecret(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) ([]byte, error) {
	cacheKey := secretCacheKey(ref.Key, cacheKindSecret, ref.Property)
	if v, ok := c.cacheGet(cacheKey); ok {
		return v, nil
	}

	accessToken, t, err := c.getToken(ctx)
	if err != nil {
		return nil, err
	}
	ciphers, err := c.listCiphersWithToken(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	cipher, err := findCipherByName(ciphers, ref.Key, t)
	if err != nil {
		return nil, err
	}
	var out []byte
	if ref.Property != "" {
		out, err = getCipherProperty(cipher, ref.Property, t)
	} else {
		out, err = getCipherValue(cipher, ref.Key, t)
	}
	if err != nil {
		return nil, err
	}
	c.cacheAdd(cacheKey, out)
	return out, nil
}

// getCipherProperty looks up a named property from a cipher's custom fields,
// falling back to the cipher's Notes JSON for secrets written by this provider.
func getCipherProperty(cipher *vaultwardenCipher, property string, t *cachedToken) ([]byte, error) {
	enc, mac := t.keysFor(*cipher)
	for _, f := range cipher.Fields {
		name, err := crypto.DecryptString(f.Name, enc, mac)
		if err != nil {
			continue
		}
		if name == property {
			val, err := crypto.DecryptString(f.Value, enc, mac)
			if err != nil {
				return nil, fmt.Errorf("vaultwarden: decrypting field value: %w", err)
			}
			return []byte(val), nil
		}
	}
	if v := getCipherPropertyFromNotes(cipher, property, t); v != nil {
		return v, nil
	}
	return nil, fmt.Errorf("vaultwarden: field %q not found in secret %q", property, cipher.Name)
}

// getCipherPropertyFromNotes attempts to extract a property from Notes JSON.
func getCipherPropertyFromNotes(cipher *vaultwardenCipher, property string, t *cachedToken) []byte {
	if cipher.Notes == "" {
		return nil
	}
	enc, mac := t.keysFor(*cipher)
	notes, err := crypto.DecryptString(cipher.Notes, enc, mac)
	if err != nil {
		return nil
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal([]byte(notes), &obj) != nil {
		return nil
	}
	if raw, ok := obj[property]; ok {
		return jsonRawToBytes(raw)
	}
	return nil
}

// getCipherValue returns the primary value of a cipher:
// Notes for SecureNote (type 2), password for Login (type 1).
func getCipherValue(cipher *vaultwardenCipher, key string, t *cachedToken) ([]byte, error) {
	enc, mac := t.keysFor(*cipher)
	if cipher.Type == 2 {
		val, err := crypto.DecryptString(cipher.Notes, enc, mac)
		if err != nil {
			return nil, fmt.Errorf("vaultwarden: decrypting notes: %w", err)
		}
		return []byte(val), nil
	}
	if cipher.Login != nil {
		val, err := crypto.DecryptString(cipher.Login.Password, enc, mac)
		if err != nil {
			return nil, fmt.Errorf("vaultwarden: decrypting password: %w", err)
		}
		return []byte(val), nil
	}
	return nil, fmt.Errorf("vaultwarden: secret %q has no usable value", key)
}

// GetSecretMap returns a map of keys to values by parsing the cipher's decrypted notes as JSON.
// The whole map is cached as one entry (cacheKindMap). ref.Property is ignored
// by this provider, so it is not part of the cache key.
func (c *Client) GetSecretMap(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	cacheKey := secretCacheKey(ref.Key, cacheKindMap, "")
	if m, ok := c.cacheGetMap(cacheKey); ok {
		return m, nil
	}

	accessToken, t, err := c.getToken(ctx)
	if err != nil {
		return nil, err
	}

	ciphers, err := c.listCiphersWithToken(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	cipher, err := findCipherByName(ciphers, ref.Key, t)
	if err != nil {
		return nil, err
	}

	if cipher.Notes == "" {
		return nil, fmt.Errorf("vaultwarden: secret %q has empty notes; cannot produce map", ref.Key)
	}

	enc, mac := t.keysFor(*cipher)
	notes, err := crypto.DecryptString(cipher.Notes, enc, mac)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: decrypting notes for map: %w", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(notes), &raw); err != nil {
		return nil, fmt.Errorf("vaultwarden: notes for %q are not valid JSON: %w", ref.Key, err)
	}

	out := make(map[string][]byte, len(raw))
	for k, v := range raw {
		out[k] = jsonRawToBytes(v)
	}
	c.cacheAddMap(cacheKey, out)
	return out, nil
}

// GetAllSecrets returns all ciphers (optionally filtered by name regexp) as a name→value map.
func (c *Client) GetAllSecrets(ctx context.Context, ref esv1.ExternalSecretFind) (map[string][]byte, error) {
	accessToken, t, err := c.getToken(ctx)
	if err != nil {
		return nil, err
	}
	ciphers, err := c.listCiphersWithToken(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	nameRe, err := compileNameRegexp(ref)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte)
	for i := range ciphers {
		name, val, ok := decryptCipherEntry(&ciphers[i], nameRe, t)
		if ok {
			out[name] = val
		}
	}
	return out, nil
}

// compileNameRegexp returns a compiled regexp from the find ref, or nil if none is set.
func compileNameRegexp(ref esv1.ExternalSecretFind) (*regexp.Regexp, error) {
	if ref.Name == nil || ref.Name.RegExp == "" {
		return nil, nil
	}
	re, err := regexp.Compile(ref.Name.RegExp)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: invalid name regexp %q: %w", ref.Name.RegExp, err)
	}
	return re, nil
}

// decryptCipherEntry decrypts a cipher's name and value, applying the optional name filter.
// Returns (name, value, true) on success or ("", nil, false) if the entry should be skipped.
func decryptCipherEntry(cipher *vaultwardenCipher, nameRe *regexp.Regexp, t *cachedToken) (string, []byte, bool) {
	if cipher.DeletedDate != nil {
		return "", nil, false
	}
	enc, mac := t.keysFor(*cipher)
	name, err := crypto.DecryptString(cipher.Name, enc, mac)
	if err != nil || (nameRe != nil && !nameRe.MatchString(name)) {
		return "", nil, false
	}
	val, err := decryptCipherPrimaryValue(cipher, t)
	if err != nil {
		return "", nil, false
	}
	return name, []byte(val), true
}

// decryptCipherPrimaryValue returns the primary plaintext value of a cipher.
func decryptCipherPrimaryValue(cipher *vaultwardenCipher, t *cachedToken) (string, error) {
	enc, mac := t.keysFor(*cipher)
	if cipher.Type == 2 {
		return crypto.DecryptString(cipher.Notes, enc, mac)
	}
	if cipher.Login != nil {
		return crypto.DecryptString(cipher.Login.Password, enc, mac)
	}
	return "", nil
}

// PushSecret writes a secret value to Vaultwarden as a SecureNote cipher.
// It creates the cipher if it doesn't exist, or updates it if it does. An
// ambiguous name (more than one item with that name in scope) is an error so the
// wrong item is never overwritten.
func (c *Client) PushSecret(ctx context.Context, secret *corev1.Secret, data esv1.PushSecretData) error {
	accessToken, t, err := c.getToken(ctx)
	if err != nil {
		return err
	}
	value, err := buildPushValue(secret, data)
	if err != nil {
		return err
	}
	cipherName := data.GetRemoteKey()
	bodyBytes, err := c.buildCipherBody(cipherName, string(value), t)
	if err != nil {
		return err
	}
	ciphers, err := c.listCiphersWithToken(ctx, accessToken)
	if err != nil {
		return err
	}
	existing, err := findUniqueCipherByName(ciphers, cipherName, t)
	if err != nil {
		return err
	}
	if err := c.upsertCipher(ctx, accessToken, existing, bodyBytes); err != nil {
		return err
	}
	// A write invalidates every cached read of the item it touched, so a push
	// followed by a read in the same window cannot serve the pre-write value.
	c.invalidateItem(cipherName)
	if existing != nil && existing.ID != cipherName {
		c.invalidateItem(existing.ID)
	}
	return nil
}

// buildPushValue extracts the value to push from the Kubernetes secret.
// If a specific key is requested, that key's raw bytes are returned.
// Otherwise all data keys are JSON-marshalled as a string map.
func buildPushValue(secret *corev1.Secret, data esv1.PushSecretData) ([]byte, error) {
	if key := data.GetSecretKey(); key != "" {
		val, ok := secret.Data[key]
		if !ok {
			return nil, fmt.Errorf("vaultwarden: key %q not found in secret %s/%s", key, secret.Namespace, secret.Name)
		}
		return val, nil
	}
	// Convert []byte values to strings so json.Marshal does not base64-encode them,
	// preserving round-trip fidelity with GetSecretMap.
	strData := make(map[string]string, len(secret.Data))
	for k, v := range secret.Data {
		strData[k] = string(v)
	}
	b, err := json.Marshal(strData)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: marshalling secret data: %w", err)
	}
	return b, nil
}

// buildCipherBody encrypts the cipher name and notes and serialises the body.
// When t.orgID is set, the cipher is encrypted with the org's symkey and
// tagged with the org's UUID so Vaultwarden stores it in the org vault.
func (c *Client) buildCipherBody(name, notes string, t *cachedToken) ([]byte, error) {
	// Pick encryption keys based on scope.
	enc, mac := t.symEncKey, t.symMacKey
	if t.orgID != "" {
		enc, mac = t.orgEncKey, t.orgMacKey
	}

	encName, err := crypto.EncryptString(name, enc, mac)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: encrypting cipher name: %w", err)
	}
	encNotes, err := crypto.EncryptString(notes, enc, mac)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: encrypting cipher notes: %w", err)
	}
	body := cipherCreateBody{
		Type:       2,
		Name:       encName,
		Notes:      encNotes,
		SecureNote: &secureNoteObj{Type: 0},
	}
	if t.orgID != "" {
		body.OrganizationID = t.orgID
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: marshalling cipher body: %w", err)
	}
	return b, nil
}

// upsertCipher sends a PUT (update) or POST (create) request depending on whether existing is set.
func (c *Client) upsertCipher(ctx context.Context, accessToken string, existing *vaultwardenCipher, bodyBytes []byte) error {
	base := strings.TrimRight(c.provider.URL, "/")
	var method, url string
	if existing != nil {
		method = http.MethodPut
		url = fmt.Sprintf("%s/api/ciphers/%s", base, existing.ID)
	} else {
		method = http.MethodPost
		url = base + "/api/ciphers"
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("vaultwarden: building cipher request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", bearerPrefix+accessToken)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("vaultwarden: cipher request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("vaultwarden: cipher request returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// DeleteSecret deletes the cipher matching the remote ref's key. Idempotent —
// returns nil if not found. An ambiguous name is an error: a delete must never
// guess which of several duplicates the caller meant.
func (c *Client) DeleteSecret(ctx context.Context, remoteRef esv1.PushSecretRemoteRef) error {
	accessToken, t, err := c.getToken(ctx)
	if err != nil {
		return err
	}

	ciphers, err := c.listCiphersWithToken(ctx, accessToken)
	if err != nil {
		return err
	}

	cipher, err := findUniqueCipherByName(ciphers, remoteRef.GetRemoteKey(), t)
	if err != nil {
		return err
	}
	if cipher == nil {
		// Not found — idempotent delete.
		return nil
	}

	base := strings.TrimRight(c.provider.URL, "/")
	deleteURL := fmt.Sprintf("%s/api/ciphers/%s", base, cipher.ID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, deleteURL, nil)
	if err != nil {
		return fmt.Errorf("vaultwarden: building delete request: %w", err)
	}
	req.Header.Set("Authorization", bearerPrefix+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("vaultwarden: deleting cipher: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("vaultwarden: delete cipher returned HTTP %d", resp.StatusCode)
	}
	c.invalidateItem(remoteRef.GetRemoteKey())
	c.invalidateItem(cipher.ID)
	return nil
}

// SecretExists returns true if a cipher with the given remote key name exists in the vault.
// An ambiguous name is an error rather than an arbitrary true/false.
func (c *Client) SecretExists(ctx context.Context, remoteRef esv1.PushSecretRemoteRef) (bool, error) {
	accessToken, t, err := c.getToken(ctx)
	if err != nil {
		return false, err
	}

	ciphers, err := c.listCiphersWithToken(ctx, accessToken)
	if err != nil {
		return false, err
	}

	cipher, err := findUniqueCipherByName(ciphers, remoteRef.GetRemoteKey(), t)
	if err != nil {
		return false, err
	}
	return cipher != nil, nil
}

// listCiphersWithToken retrieves all ciphers via /api/sync and returns only
// those in the configured scope (personal, one org, and — when configured — one
// collection within that org).
//
// The collection name→UUID resolution also happens here because /api/sync is
// the only call that returns the collection list, so a collection scope costs
// no extra request.
func (c *Client) listCiphersWithToken(ctx context.Context, accessToken string) ([]vaultwardenCipher, error) {
	url := strings.TrimRight(c.provider.URL, "/") + "/api/sync?excludeDomains=true"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: building sync request: %w", err)
	}
	req.Header.Set("Authorization", bearerPrefix+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vaultwarden: sync: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vaultwarden: sync returned status %d", resp.StatusCode)
	}

	var sync syncResponse
	if err := json.NewDecoder(resp.Body).Decode(&sync); err != nil {
		return nil, fmt.Errorf("vaultwarden: decoding sync: %w", err)
	}

	orgID := c.cachedOrgID()
	collectionID, err := resolveCollectionID(sync.Collections, c.provider, orgID)
	if err != nil {
		return nil, err
	}
	scoped := filterCiphersByScope(sync.Ciphers, orgID)
	return filterCiphersByCollection(scoped, collectionID), nil
}

// cachedOrgID returns the orgID stored on the active cachedToken
// (empty string for personal-vault scope). Reads under the existing
// cache mutex.
func (c *Client) cachedOrgID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		return ""
	}
	return c.cache.orgID
}

// cipherName decrypts a cipher's name. ok is false for deleted items and for
// any item whose name does not decrypt under the active scope's keys.
func cipherName(c *vaultwardenCipher, t *cachedToken) (string, bool) {
	if c.DeletedDate != nil {
		return "", false
	}
	enc, mac := t.keysFor(*c)
	name, err := crypto.DecryptString(c.Name, enc, mac)
	if err != nil {
		return "", false
	}
	return name, true
}

// findCipherByID returns the cipher with the given UUID, or nil. Item ids are
// addressable so that a duplicated name stays resolvable.
func findCipherByID(ciphers []vaultwardenCipher, id string) *vaultwardenCipher {
	for i := range ciphers {
		if ciphers[i].DeletedDate == nil && ciphers[i].ID == id {
			return &ciphers[i]
		}
	}
	return nil
}

// findCiphersByName returns every cipher whose decrypted name equals target,
// sorted by id so callers and tests see a deterministic order.
func findCiphersByName(ciphers []vaultwardenCipher, target string, t *cachedToken) []*vaultwardenCipher {
	var out []*vaultwardenCipher
	for i := range ciphers {
		if name, ok := cipherName(&ciphers[i], t); ok && name == target {
			out = append(out, &ciphers[i])
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ambiguousRefError is returned when a reference matches more than one item in
// the store's resolved scope. The wording follows ESO's own findSecretByRef
// convention ("more than one secret found for ..."), and the candidate ids let
// the caller disambiguate instead of guessing.
func ambiguousRefError(target string, matches []*vaultwardenCipher) error {
	ids := make([]string, 0, len(matches))
	for _, m := range matches {
		ids = append(ids, m.ID)
	}
	sort.Strings(ids)
	return fmt.Errorf("vaultwarden: more than one secret found for key %q (candidates: %s); narrow the store scope with collectionId/collectionName, or use one of the candidate ids as remoteRef.key",
		target, strings.Join(ids, ", "))
}

// findCipherByName resolves a read ref to exactly one cipher.
//
// Resolution order:
//  1. an exact match on the cipher UUID, so a duplicate that cannot be renamed
//     is still addressable deterministically;
//  2. an exact match on the decrypted item name.
//
// A name matching more than one cipher in scope is an error listing the
// candidate ids — never a silent first-match win.
func findCipherByName(ciphers []vaultwardenCipher, target string, t *cachedToken) (*vaultwardenCipher, error) {
	if c := findCipherByID(ciphers, target); c != nil {
		return c, nil
	}
	matches := findCiphersByName(ciphers, target, t)
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("vaultwarden: secret %q not found", target)
	case 1:
		return matches[0], nil
	default:
		return nil, ambiguousRefError(target, matches)
	}
}

// findUniqueCipherByName is the write-path counterpart. nil, nil means "no such
// item" (idempotent delete, or create-on-push). More than one match is an error
// so a mutating call can never pick the wrong duplicate to overwrite or delete.
func findUniqueCipherByName(ciphers []vaultwardenCipher, target string, t *cachedToken) (*vaultwardenCipher, error) {
	if c := findCipherByID(ciphers, target); c != nil {
		return c, nil
	}
	matches := findCiphersByName(ciphers, target, t)
	switch len(matches) {
	case 0:
		return nil, nil
	case 1:
		return matches[0], nil
	default:
		return nil, ambiguousRefError(target, matches)
	}
}

// jsonRawToBytes converts a json.RawMessage to []byte.
// For JSON strings the surrounding quotes are stripped; other types are returned as-is.
func jsonRawToBytes(raw json.RawMessage) []byte {
	if len(raw) > 1 && raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			return []byte(s)
		}
	}
	return []byte(raw)
}
