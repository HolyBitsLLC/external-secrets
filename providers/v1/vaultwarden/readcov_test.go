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
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/external-secrets/external-secrets/providers/v1/vaultwarden/internal/crypto"
)

// TestGetSecretLoginUsername exercises the login-username gap: a login cipher
// must expose both `username` and `password`, and a property-less read must keep
// returning the password.
func TestGetSecretLoginUsername(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, nil)
	fv.setCiphers(loginUserCipher(t, "id-1", "app-login", "svc-account", "hunter2"))

	got, err := c.GetSecret(ctx, ref("app-login", "username"))
	require.NoError(t, err)
	assert.Equal(t, "svc-account", string(got))

	got, err = c.GetSecret(ctx, ref("app-login", "password"))
	require.NoError(t, err)
	assert.Equal(t, "hunter2", string(got))

	got, err = c.GetSecret(ctx, ref("app-login", ""))
	require.NoError(t, err)
	assert.Equal(t, "hunter2", string(got), "no-property read must stay the password")
}

// TestGetSecretSSHKeyProperties exercises the SSH-key gap: a type-5 item must
// expose privateKey/publicKey/keyFingerprint, accept `fingerprint` as an alias,
// and return the private key as its primary value.
func TestGetSecretSSHKeyProperties(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, nil)
	fv.setCiphers(sshCipher(t, "ssh-1", "deploy-key", "PRIVATE-KEY-PEM", "ssh-ed25519 AAAA", "SHA256:abc"))

	for _, tc := range []struct{ prop, want string }{
		{"privateKey", "PRIVATE-KEY-PEM"},
		{"publicKey", "ssh-ed25519 AAAA"},
		{"keyFingerprint", "SHA256:abc"},
		{"fingerprint", "SHA256:abc"},
		{"", "PRIVATE-KEY-PEM"},
	} {
		got, err := c.GetSecret(ctx, ref("deploy-key", tc.prop))
		require.NoErrorf(t, err, "property %q", tc.prop)
		assert.Equalf(t, tc.want, string(got), "property %q", tc.prop)
	}
}

// TestGetSecretSSHAbsentOptionalFieldFallsThrough verifies an omitted optional
// SSH field is reported missing rather than silently answered with another
// field of the same item.
func TestGetSecretSSHAbsentOptionalFieldFallsThrough(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, nil)
	fv.setCiphers(sshCipher(t, "ssh-1", "deploy", "PRIV", "", ""))

	_, err := c.GetSecret(ctx, ref("deploy", "publicKey"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestGetSecretCustomFieldWinsOverBuiltin pins the precedence: an explicit
// custom field keeps overriding the built-in property, so the existing
// bitwarden-fields semantics cannot regress.
func TestGetSecretCustomFieldWinsOverBuiltin(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, nil)
	ciph := sshCipher(t, "ssh-1", "deploy", "PRIV", "", "")
	ciph.Fields = []cipherField{{
		Name:  enc(t, "privateKey", testEncKey, testMacKey),
		Value: enc(t, "FIELD-VALUE", testEncKey, testMacKey),
	}}
	fv.setCiphers(ciph)

	got, err := c.GetSecret(ctx, ref("deploy", "privateKey"))
	require.NoError(t, err)
	assert.Equal(t, "FIELD-VALUE", string(got))
}

// TestGetSecretNotePropertyStillWorks is the notes/fields regression guard for
// the new resolution order.
func TestGetSecretNotePropertyStillWorks(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, nil)
	fv.setCiphers(noteCipher(t, "n-1", "cfg", `{"api_key":"abc123","host":"example.test"}`, ""))

	got, err := c.GetSecret(ctx, ref("cfg", "api_key"))
	require.NoError(t, err)
	assert.Equal(t, "abc123", string(got))
}

// TestGetSecretAttachmentV1UsesCipherKey covers a legacy attachment (no Key
// field), decrypted with the cipher key, addressed by filename.
func TestGetSecretAttachmentV1UsesCipherKey(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, nil)
	ciph := noteCipher(t, "c-1", "cert-item", `{"kind":"cert"}`, "")
	addAttachment(&ciph, t, "att-1", "cert.pem", nil)
	fv.setCiphers(ciph)

	blob, err := crypto.EncryptBlob([]byte("PEM-DATA"), testEncKey, testMacKey)
	require.NoError(t, err)
	fv.setAttachment("c-1", "att-1", blob)

	got, err := c.GetSecret(ctx, ref("cert-item", "cert.pem"))
	require.NoError(t, err)
	assert.Equal(t, "PEM-DATA", string(got))
}

// TestGetSecretAttachmentV2UsesPerAttachmentKey covers a v2 attachment whose
// 64-byte key is wrapped with the cipher key and used to decrypt the blob.
func TestGetSecretAttachmentV2UsesPerAttachmentKey(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, nil)
	ciph := noteCipher(t, "c-1", "item", "", "")
	attEnc := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	attMac := []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	addAttachment(&ciph, t, "att-1", "secret.txt", append(append([]byte{}, attEnc...), attMac...))
	fv.setCiphers(ciph)

	blob, err := crypto.EncryptBlob([]byte("v2-PAYLOAD"), attEnc, attMac)
	require.NoError(t, err)
	fv.setAttachment("c-1", "att-1", blob)

	got, err := c.GetSecret(ctx, ref("item", "secret.txt"))
	require.NoError(t, err)
	assert.Equal(t, "v2-PAYLOAD", string(got))
}

// TestGetSecretAttachmentByID verifies attachments are also addressable by id,
// the escape hatch for duplicate filenames.
func TestGetSecretAttachmentByID(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, nil)
	ciph := noteCipher(t, "c-1", "item", "", "")
	addAttachment(&ciph, t, "att-9", "opaque.bin", nil)
	fv.setCiphers(ciph)

	blob, err := crypto.EncryptBlob([]byte("BY-ID"), testEncKey, testMacKey)
	require.NoError(t, err)
	fv.setAttachment("c-1", "att-9", blob)

	got, err := c.GetSecret(ctx, ref("item", "att-9"))
	require.NoError(t, err)
	assert.Equal(t, "BY-ID", string(got))
}

// TestGetSecretAttachmentWrongKeyFails verifies a blob that does not match the
// selected key fails the MAC check rather than returning garbage.
func TestGetSecretAttachmentWrongKeyFails(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, nil)
	ciph := noteCipher(t, "c-1", "item", "", "")
	addAttachment(&ciph, t, "att-1", "a.bin", nil)
	fv.setCiphers(ciph)

	otherEnc := []byte("99999999999999999999999999999999")
	otherMac := []byte("88888888888888888888888888888888")
	blob, err := crypto.EncryptBlob([]byte("TOP-SECRET"), otherEnc, otherMac)
	require.NoError(t, err)
	fv.setAttachment("c-1", "att-1", blob)

	_, err = c.GetSecret(ctx, ref("item", "a.bin"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ciphertext")
}

// TestGetSecretAttachmentMissing covers the not-found path (property matches no
// field, notes key or attachment).
func TestGetSecretAttachmentMissing(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, nil)
	fv.setCiphers(noteCipher(t, "c-1", "item", "", ""))

	_, err := c.GetSecret(ctx, ref("item", "nope.pem"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestGetSecretAttachmentDownloadError covers a non-200 download response.
func TestGetSecretAttachmentDownloadError(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, nil)
	ciph := noteCipher(t, "c-1", "item", "", "")
	addAttachment(&ciph, t, "att-1", "gone.bin", nil)
	fv.setCiphers(ciph)
	// No blob registered for this pair: the fake server answers 404.

	_, err := c.GetSecret(ctx, ref("item", "gone.bin"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

// TestGetSecretAmbiguousAttachmentFilename verifies duplicate attachment names
// are never silently resolved.
func TestGetSecretAmbiguousAttachmentFilename(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, nil)
	ciph := noteCipher(t, "c-1", "item", "", "")
	addAttachment(&ciph, t, "att-1", "dup.txt", nil)
	addAttachment(&ciph, t, "att-2", "dup.txt", nil)
	fv.setCiphers(ciph)

	_, err := c.GetSecret(ctx, ref("item", "dup.txt"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "more than one attachment")
	assert.Contains(t, err.Error(), "att-1")
	assert.Contains(t, err.Error(), "att-2")
}

// TestGetSecretUsernameAmbiguousCipher verifies the ambiguity discipline also
// gates the new username path: a duplicated item name is an error.
func TestGetSecretUsernameAmbiguousCipher(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, nil)
	fv.setCiphers(
		loginUserCipher(t, "aaaa-1111", "dup", "u1", "p1"),
		loginUserCipher(t, "bbbb-2222", "dup", "u2", "p2"),
	)

	_, err := c.GetSecret(ctx, ref("dup", "username"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "more than one secret found")
}

// TestGetSecretMapStructuralLogin covers the map fallback for a login item that
// has no notes JSON.
func TestGetSecretMapStructuralLogin(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, nil)
	fv.setCiphers(loginUserCipher(t, "l-1", "app", "alice", "pw"))

	m, err := c.GetSecretMap(ctx, ref("app", ""))
	require.NoError(t, err)
	assert.Equal(t, []byte("alice"), m["username"])
	assert.Equal(t, []byte("pw"), m["password"])
}

// TestGetSecretMapStructuralSSH covers the map fallback for a type-5 item.
func TestGetSecretMapStructuralSSH(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, nil)
	fv.setCiphers(sshCipher(t, "s-1", "deploy", "PRIV", "PUB", "FP"))

	m, err := c.GetSecretMap(ctx, ref("deploy", ""))
	require.NoError(t, err)
	assert.Equal(t, []byte("PRIV"), m["privateKey"])
	assert.Equal(t, []byte("PUB"), m["publicKey"])
	assert.Equal(t, []byte("FP"), m["keyFingerprint"])
}

// TestGetSecretMapNotesStillWins pins the historical contract: a notes-JSON item
// yields exactly its JSON keys.
func TestGetSecretMapNotesStillWins(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, nil)
	fv.setCiphers(noteCipher(t, "n-1", "cfg", `{"a":"1","b":"2"}`, ""))

	m, err := c.GetSecretMap(ctx, ref("cfg", ""))
	require.NoError(t, err)
	assert.Equal(t, map[string][]byte{"a": []byte("1"), "b": []byte("2")}, m)
}

// TestGetSecretMapNoNotesNoFieldsErrors verifies an empty item still errors
// rather than yielding an empty secret.
func TestGetSecretMapNoNotesNoFieldsErrors(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, nil)
	fv.setCiphers(vaultwardenCipher{
		ID:   "e-1",
		Type: cipherTypeLogin,
		Name: enc(t, "empty", testEncKey, testMacKey),
	})

	_, err := c.GetSecretMap(ctx, ref("empty", ""))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot produce map")
}

// TestGetSecretUsernameCached verifies the new property reads flow through the
// bounded value cache: a second read must not hit /api/sync again.
func TestGetSecretUsernameCached(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, cacheConfig(time.Minute, 10))
	fv.setCiphers(loginUserCipher(t, "l-1", "app", "alice", "pw"))

	first, err := c.GetSecret(ctx, ref("app", "username"))
	require.NoError(t, err)
	second, err := c.GetSecret(ctx, ref("app", "username"))
	require.NoError(t, err)

	assert.Equal(t, "alice", string(first))
	assert.Equal(t, "alice", string(second))
	assert.Equal(t, 1, fv.count("sync"), "second read must be served from the value cache")
}

// TestGetSecretAttachmentCached verifies an attachment download is cached too.
func TestGetSecretAttachmentCached(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, cacheConfig(time.Minute, 10))
	ciph := noteCipher(t, "c-1", "item", "", "")
	addAttachment(&ciph, t, "att-1", "a.pem", nil)
	fv.setCiphers(ciph)
	blob, err := crypto.EncryptBlob([]byte("CACHED"), testEncKey, testMacKey)
	require.NoError(t, err)
	fv.setAttachment("c-1", "att-1", blob)

	for i := 0; i < 2; i++ {
		got, err := c.GetSecret(ctx, ref("item", "a.pem"))
		require.NoError(t, err)
		assert.Equal(t, "CACHED", string(got))
	}
	assert.Equal(t, 1, fv.count("attachment"), "second read must not re-download the blob")
}
