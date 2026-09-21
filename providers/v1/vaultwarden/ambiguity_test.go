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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

// TestGetSecretAmbiguousNameFailsLoudly is the regression test for the defect
// class that took out Cloudflare credentials, a cert-manager DNS-01 challenge
// and two ExternalSecrets: a duplicated item name must never silently resolve to
// whichever copy happened to be first.
func TestGetSecretAmbiguousNameFailsLoudly(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, nil)
	fv.setCiphers(
		loginCipher(t, "aaaa-1111", "cloudflare-api-token", "stale-value", ""),
		loginCipher(t, "bbbb-2222", "cloudflare-api-token", "live-value", ""),
	)

	_, err := c.GetSecret(ctx, ref("cloudflare-api-token", ""))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "more than one secret found", "must follow ESO's findSecretByRef wording")
	assert.Contains(t, err.Error(), "aaaa-1111")
	assert.Contains(t, err.Error(), "bbbb-2222")
}

// TestAmbiguityIsDeterministic pins the candidate ordering so the error message
// is stable regardless of the order the vault returned items in.
func TestAmbiguityIsDeterministic(t *testing.T) {
	tok := &cachedToken{symEncKey: testEncKey, symMacKey: testMacKey}
	forward := []vaultwardenCipher{}
	reverse := []vaultwardenCipher{}

	names := []string{"bbbb", "aaaa", "cccc"}
	for _, id := range names {
		forward = append(forward, loginCipher(t, id, "dup", "v", ""))
	}
	for i := len(names) - 1; i >= 0; i-- {
		reverse = append(reverse, loginCipher(t, names[i], "dup", "v", ""))
	}

	_, errF := findCipherByName(forward, "dup", tok)
	_, errR := findCipherByName(reverse, "dup", tok)
	require.Error(t, errF)
	require.Error(t, errR)
	assert.Equal(t, errF.Error(), errR.Error())
	assert.Contains(t, errF.Error(), "aaaa, bbbb, cccc")
}

// TestGetSecretResolvesDuplicateByNameIfItIsAnId shows the escape hatch: item
// ids are addressable, so a duplicate that cannot be renamed is still usable.
func TestGetSecretResolvesDuplicateByNameIfItIsAnId(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, nil)
	fv.setCiphers(
		loginCipher(t, "aaaa-1111", "cloudflare-api-token", "stale-value", ""),
		loginCipher(t, "bbbb-2222", "cloudflare-api-token", "live-value", ""),
	)

	got, err := c.GetSecret(ctx, ref("bbbb-2222", ""))
	require.NoError(t, err)
	assert.Equal(t, "live-value", string(got))
}

// TestFindCipherByIDIgnoresDeletedItems verifies a soft-deleted item cannot be
// revived by referencing its id.
func TestFindCipherByIDIgnoresDeletedItems(t *testing.T) {
	tok := &cachedToken{symEncKey: testEncKey, symMacKey: testMacKey}
	ciphers := []vaultwardenCipher{{
		ID:          "deleted-1",
		Type:        1,
		Name:        enc(t, "gone", testEncKey, testMacKey),
		DeletedDate: "2026-01-01T00:00:00Z",
	}}

	_, err := findCipherByName(ciphers, "deleted-1", tok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestFindCipherByNameSingleMatch covers the ordinary path.
func TestFindCipherByNameSingleMatch(t *testing.T) {
	tok := &cachedToken{symEncKey: testEncKey, symMacKey: testMacKey}
	got, err := findCipherByName([]vaultwardenCipher{
		loginCipher(t, "id-1", "app", "value", ""),
	}, "app", tok)
	require.NoError(t, err)
	assert.Equal(t, "id-1", got.ID)
}

// TestFindCipherByNameNotFound covers the missing-item path, whose error text
// ESO uses to decide DeletionPolicy handling through NoSecretErr semantics.
func TestFindCipherByNameNotFound(t *testing.T) {
	tok := &cachedToken{symEncKey: testEncKey, symMacKey: testMacKey}
	_, err := findCipherByName(nil, "absent", tok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `secret "absent" not found`)
}

// TestPushSecretRefusesAmbiguousName verifies the write path cannot overwrite an
// arbitrary duplicate.
func TestPushSecretRefusesAmbiguousName(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, nil)
	fv.setCiphers(
		loginCipher(t, "aaaa-1111", "dup", "one", ""),
		loginCipher(t, "bbbb-2222", "dup", "two", ""),
	)

	err := c.PushSecret(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "src"},
		Data:       map[string][]byte{"data": []byte("value")},
	}, stubPushSecretData{secretKey: "data", remoteKey: "dup"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "more than one secret found")
	assert.Equal(t, 0, fv.count("update"), "no cipher may be overwritten")
	assert.Equal(t, 0, fv.count("create"), "no cipher may be created")
}

// TestDeleteSecretRefusesAmbiguousName verifies the delete path cannot remove an
// arbitrary duplicate.
func TestDeleteSecretRefusesAmbiguousName(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, nil)
	fv.setCiphers(
		loginCipher(t, "aaaa-1111", "dup", "one", ""),
		loginCipher(t, "bbbb-2222", "dup", "two", ""),
	)

	err := c.DeleteSecret(ctx, stubPushSecretRemoteRef{remoteKey: "dup"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "more than one secret found")
	assert.Equal(t, 0, fv.count("delete"))
}

// TestSecretExistsRefusesAmbiguousName verifies the existence probe does not
// answer arbitrarily for a duplicated name.
func TestSecretExistsRefusesAmbiguousName(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, nil)
	fv.setCiphers(
		loginCipher(t, "aaaa-1111", "dup", "one", ""),
		loginCipher(t, "bbbb-2222", "dup", "two", ""),
	)

	_, err := c.SecretExists(ctx, stubPushSecretRemoteRef{remoteKey: "dup"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "more than one secret found")
}

// TestSecretExistsSingleMatchStillWorks guards against the ambiguity check
// swallowing the happy path.
func TestSecretExistsSingleMatchStillWorks(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, nil)
	fv.setCiphers(loginCipher(t, "id-1", "app", "value", ""))

	exists, err := c.SecretExists(ctx, stubPushSecretRemoteRef{remoteKey: "app"})
	require.NoError(t, err)
	assert.True(t, exists)

	exists, err = c.SecretExists(ctx, stubPushSecretRemoteRef{remoteKey: "absent"})
	require.NoError(t, err)
	assert.False(t, exists)
}

// TestAmbiguityErrorNamesTheRemedy keeps the operator-facing advice in the
// message: the error is only actionable if it says how to fix the collision.
func TestAmbiguityErrorNamesTheRemedy(t *testing.T) {
	tok := &cachedToken{symEncKey: testEncKey, symMacKey: testMacKey}
	_, err := findCipherByName([]vaultwardenCipher{
		loginCipher(t, "id-1", "dup", "one", ""),
		loginCipher(t, "id-2", "dup", "two", ""),
	}, "dup", tok)

	require.Error(t, err)
	assert.True(t,
		strings.Contains(err.Error(), "collectionId/collectionName") && strings.Contains(err.Error(), "remoteRef.key"),
		"error must name both remedies, got: %s", err.Error())
}

var _ esv1.PushSecretData = stubPushSecretData{}
var _ esv1.PushSecretRemoteRef = stubPushSecretRemoteRef{}
