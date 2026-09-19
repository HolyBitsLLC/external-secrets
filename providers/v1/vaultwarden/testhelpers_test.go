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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/providers/v1/vaultwarden/internal/crypto"
)

// fakeVault is a stand-in for the two Vaultwarden endpoints the provider reads
// and writes: GET /api/sync and the cipher write verbs. Every request is
// counted, so cache behaviour can be asserted as an exact call count instead of
// as a timing guess.
type fakeVault struct {
	srv *httptest.Server

	mu          sync.Mutex
	calls       map[string]int
	ciphers     []vaultwardenCipher
	collections []collectionEntry
}

func newFakeVault(t *testing.T) *fakeVault {
	t.Helper()
	f := &fakeVault{calls: map[string]int{}}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/sync", func(w http.ResponseWriter, _ *http.Request) {
		f.inc("sync")
		f.mu.Lock()
		resp := syncResponse{Ciphers: f.ciphers, Collections: f.collections}
		f.mu.Unlock()
		writeJSON(t, w, resp)
	})
	mux.HandleFunc("POST /api/ciphers", func(w http.ResponseWriter, _ *http.Request) {
		f.inc("create")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("PUT /api/ciphers/{id}", func(w http.ResponseWriter, _ *http.Request) {
		f.inc("update")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("DELETE /api/ciphers/{id}", func(w http.ResponseWriter, _ *http.Request) {
		f.inc("delete")
		w.WriteHeader(http.StatusOK)
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("fake vault: encoding response: %v", err)
	}
}

func (f *fakeVault) inc(kind string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[kind]++
}

// count returns how many times a request kind was served.
func (f *fakeVault) count(kind string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[kind]
}

func (f *fakeVault) setCiphers(ciphers ...vaultwardenCipher) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ciphers = ciphers
}

func (f *fakeVault) setCollections(collections ...collectionEntry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.collections = collections
}

// testKeys are the deterministic symmetric key bytes every harness client uses.
var (
	testEncKey = []byte("0123456789abcdef0123456789abcdef")
	testMacKey = []byte("fedcba9876543210fedcba9876543210")
)

// newHarness builds a Client wired to a fake Vaultwarden with a pre-seeded,
// unexpired token cache. Pre-seeding skips the token/profile/derive round trip
// entirely (getSymKey short-circuits on a live cachedToken), so tests exercise
// exactly the cipher read path they care about and no K8s client is needed.
func newHarness(t *testing.T, cfg *esv1.CacheConfig) (*Client, *fakeVault) {
	t.Helper()
	fv := newFakeVault(t)
	tok := &cachedToken{
		accessToken: "test-access-token",
		symEncKey:   append([]byte(nil), testEncKey...),
		symMacKey:   append([]byte(nil), testMacKey...),
		expiresAt:   time.Now().Add(time.Hour),
	}
	c := &Client{
		httpClient:  fv.srv.Client(),
		provider:    &esv1.VaultwardenProvider{URL: fv.srv.URL, Cache: cfg},
		namespace:   "default",
		store:       &esv1.SecretStore{},
		cache:       tok,
		secretCache: newSecretCache(cfg),
	}
	return c, fv
}

// enc encrypts a fixture value with the harness key material.
func enc(t *testing.T, plaintext string, encKey, macKey []byte) string {
	t.Helper()
	out, err := crypto.EncryptString(plaintext, encKey, macKey)
	if err != nil {
		t.Fatalf("encrypting fixture %q: %v", plaintext, err)
	}
	return out
}

// loginCipher builds a Login item whose password is the given plaintext.
func loginCipher(t *testing.T, id, name, password string, orgID string, collectionIDs ...string) vaultwardenCipher {
	t.Helper()
	var org any
	if orgID != "" {
		org = orgID
	}
	return vaultwardenCipher{
		ID:             id,
		Type:           1,
		Name:           enc(t, name, testEncKey, testMacKey),
		Login:          &cipherLogin{Password: enc(t, password, testEncKey, testMacKey)},
		OrganizationID: org,
		CollectionIDs:  collectionIDs,
	}
}

// noteCipher builds a SecureNote item whose notes hold the given plaintext.
func noteCipher(t *testing.T, id, name, notes string, orgID string, collectionIDs ...string) vaultwardenCipher {
	t.Helper()
	var org any
	if orgID != "" {
		org = orgID
	}
	return vaultwardenCipher{
		ID:             id,
		Type:           2,
		Name:           enc(t, name, testEncKey, testMacKey),
		Notes:          enc(t, notes, testEncKey, testMacKey),
		OrganizationID: org,
		CollectionIDs:  collectionIDs,
	}
}

// fieldCipher builds a SecureNote carrying one named custom field.
func fieldCipher(t *testing.T, id, name, field, value string) vaultwardenCipher {
	t.Helper()
	return vaultwardenCipher{
		ID:   id,
		Type: 2,
		Name: enc(t, name, testEncKey, testMacKey),
		Fields: []cipherField{{
			Name:  enc(t, field, testEncKey, testMacKey),
			Value: enc(t, value, testEncKey, testMacKey),
			Type:  0,
		}},
	}
}

// stubPushSecretData implements esv1.PushSecretData for tests.
type stubPushSecretData struct {
	secretKey string
	remoteKey string
	property  string
}

func (s stubPushSecretData) GetMetadata() *apiextensionsv1.JSON { return nil }
func (s stubPushSecretData) GetSecretKey() string               { return s.secretKey }
func (s stubPushSecretData) GetRemoteKey() string               { return s.remoteKey }
func (s stubPushSecretData) GetProperty() string                { return s.property }

// stubPushSecretRemoteRef implements esv1.PushSecretRemoteRef for tests.
type stubPushSecretRemoteRef struct {
	remoteKey string
	property  string
}

func (s stubPushSecretRemoteRef) GetRemoteKey() string { return s.remoteKey }
func (s stubPushSecretRemoteRef) GetProperty() string  { return s.property }

// cacheConfig is a small helper for building a cache spec in tests.
func cacheConfig(ttl time.Duration, maxSize int) *esv1.CacheConfig {
	return &esv1.CacheConfig{
		TTL:     metav1.Duration{Duration: ttl},
		MaxSize: maxSize,
	}
}
