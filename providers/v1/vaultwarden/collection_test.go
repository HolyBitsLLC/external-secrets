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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

// withOrgScope points a harness client at an organization. The org keys reuse
// the harness key material so org-scoped fixtures decrypt unchanged.
func withOrgScope(c *Client, orgID string) {
	c.cache.orgID = orgID
	c.cache.orgEncKey = append([]byte(nil), testEncKey...)
	c.cache.orgMacKey = append([]byte(nil), testMacKey...)
}

func TestResolveCollectionID(t *testing.T) {
	org := "11111111-1111-1111-1111-111111111111"
	other := "22222222-2222-2222-2222-222222222222"
	collections := []collectionEntry{
		{ID: "c1", OrganizationID: org, Name: "platform"},
		{ID: "c2", OrganizationID: org, Name: "duplicated-name"},
		{ID: "c3", OrganizationID: org, Name: "duplicated-name"},
		{ID: "c9", OrganizationID: other, Name: "platform"},
	}

	cases := []struct {
		name     string
		provider *esv1.VaultwardenProvider
		orgID    string
		want     string
		wantErr  string
	}{
		{
			name:     "no collection scope is a no-op",
			provider: &esv1.VaultwardenProvider{},
			orgID:    org,
			want:     "",
		},
		{
			name:     "explicit id resolves",
			provider: &esv1.VaultwardenProvider{CollectionID: "c1"},
			orgID:    org,
			want:     "c1",
		},
		{
			name:     "explicit id must exist in the org",
			provider: &esv1.VaultwardenProvider{CollectionID: "c9"},
			orgID:    org,
			wantErr:  "not found in organization",
		},
		{
			name:     "unique name resolves",
			provider: &esv1.VaultwardenProvider{CollectionName: "platform"},
			orgID:    org,
			want:     "c1",
		},
		{
			name:     "unknown name is an error",
			provider: &esv1.VaultwardenProvider{CollectionName: "absent"},
			orgID:    org,
			wantErr:  "no collection named",
		},
		{
			name:     "ambiguous name lists candidates",
			provider: &esv1.VaultwardenProvider{CollectionName: "duplicated-name"},
			orgID:    org,
			wantErr:  "more than one collection named",
		},
		{
			name:     "collection scope without an org scope is rejected",
			provider: &esv1.VaultwardenProvider{CollectionName: "platform"},
			orgID:    "",
			wantErr:  "require an organization scope",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveCollectionID(collections, tc.provider, tc.orgID)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestResolveCollectionIDAmbiguityListsBothCandidates pins the actionable detail
// in the ambiguous case.
func TestResolveCollectionIDAmbiguityListsBothCandidates(t *testing.T) {
	org := "11111111-1111-1111-1111-111111111111"
	_, err := resolveCollectionID([]collectionEntry{
		{ID: "c2", OrganizationID: org, Name: "dup"},
		{ID: "c3", OrganizationID: org, Name: "dup"},
	}, &esv1.VaultwardenProvider{CollectionName: "dup"}, org)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "c2")
	assert.Contains(t, err.Error(), "c3")
	assert.Contains(t, err.Error(), "collectionId")
}

// TestResolveCollectionIDIsOrgScoped proves a name is matched inside the
// resolved organization only, so an identically-named collection elsewhere
// cannot create a false ambiguity (or a false match).
func TestResolveCollectionIDIsOrgScoped(t *testing.T) {
	org := "11111111-1111-1111-1111-111111111111"
	other := "22222222-2222-2222-2222-222222222222"
	collections := []collectionEntry{
		{ID: "c1", OrganizationID: org, Name: "platform"},
		{ID: "c9", OrganizationID: other, Name: "platform"},
	}

	got, err := resolveCollectionID(collections, &esv1.VaultwardenProvider{CollectionName: "platform"}, org)
	require.NoError(t, err)
	assert.Equal(t, "c1", got)

	got, err = resolveCollectionID(collections, &esv1.VaultwardenProvider{CollectionName: "platform"}, other)
	require.NoError(t, err)
	assert.Equal(t, "c9", got)
}

func TestFilterCiphersByCollection(t *testing.T) {
	ciphers := []vaultwardenCipher{
		{ID: "in-1", CollectionIDs: []string{"c1", "c2"}},
		{ID: "in-2", CollectionIDs: []string{"c1"}},
		{ID: "out-1", CollectionIDs: []string{"c3"}},
		{ID: "out-2"},
	}

	assert.Equal(t, []string{"in-1", "in-2"}, cipherIDs(filterCiphersByCollection(ciphers, "c1")))
	assert.Equal(t, []string{"in-1"}, cipherIDs(filterCiphersByCollection(ciphers, "c2")))
	assert.Empty(t, filterCiphersByCollection(ciphers, "c4"))
	assert.Equal(t, cipherIDs(ciphers), cipherIDs(filterCiphersByCollection(ciphers, "")),
		"an empty collection scope must be a no-op")
}

// TestGetSecretCollectionScopeResolvesDuplicates is the end-to-end payoff: two
// items with the same name inside one organization are addressable by scoping
// the store to the collection each lives in.
func TestGetSecretCollectionScopeResolvesDuplicates(t *testing.T) {
	ctx := context.Background()
	org := "11111111-1111-1111-1111-111111111111"
	c, fv := newHarness(t, nil)
	withOrgScope(c, org)
	fv.setCiphers(
		loginCipher(t, "id-c1", "dup", "value-from-c1", org, "c1"),
		loginCipher(t, "id-c2", "dup", "value-from-c2", org, "c2"),
	)
	fv.setCollections(
		collectionEntry{ID: "c1", OrganizationID: org, Name: "platform"},
		collectionEntry{ID: "c2", OrganizationID: org, Name: "legacy"},
	)

	// Unscoped: the collision is still an error, not a coin flip.
	_, err := c.GetSecret(ctx, ref("dup", ""))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "more than one secret found")

	// Scoped by collection id.
	c.provider.CollectionID = "c1"
	got, err := c.GetSecret(ctx, ref("dup", ""))
	require.NoError(t, err)
	assert.Equal(t, "value-from-c1", string(got))

	c.provider.CollectionID = "c2"
	c.provider.CollectionName = ""
	got, err = c.GetSecret(ctx, ref("dup", ""))
	require.NoError(t, err)
	assert.Equal(t, "value-from-c2", string(got))

	// Scoped by collection name.
	c.provider.CollectionID = ""
	c.provider.CollectionName = "platform"
	got, err = c.GetSecret(ctx, ref("dup", ""))
	require.NoError(t, err)
	assert.Equal(t, "value-from-c1", string(got))
}

// TestGetSecretCollectionScopeExcludesOtherItems proves scoping narrows rather
// than merely disambiguates: an item outside the collection is invisible.
func TestGetSecretCollectionScopeExcludesOtherItems(t *testing.T) {
	ctx := context.Background()
	org := "11111111-1111-1111-1111-111111111111"
	c, fv := newHarness(t, nil)
	withOrgScope(c, org)
	fv.setCiphers(
		loginCipher(t, "id-in", "inside", "in-value", org, "c1"),
		loginCipher(t, "id-out", "outside", "out-value", org, "c2"),
	)
	fv.setCollections(collectionEntry{ID: "c1", OrganizationID: org, Name: "platform"})

	c.provider.CollectionID = "c1"

	got, err := c.GetSecret(ctx, ref("inside", ""))
	require.NoError(t, err)
	assert.Equal(t, "in-value", string(got))

	_, err = c.GetSecret(ctx, ref("outside", ""))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestGetSecretCollectionScopeWithoutOrgFailsAtReadTime proves a store that
// bypassed admission validation cannot silently ignore its collection scope.
func TestGetSecretCollectionScopeWithoutOrgFailsAtReadTime(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, nil)
	fv.setCiphers(loginCipher(t, "id-1", "app", "personal-value", ""))

	// CollectionName set but no org scope: the read layer must fail rather than
	// silently ignore the scope.
	c.provider.CollectionName = "platform"
	_, err := c.GetSecret(ctx, ref("app", ""))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "require an organization scope")
}

// TestCipherCollectionIDsNullSafe proves personal items (collectionIds absent)
// cannot match a collection filter.
func TestCipherCollectionIDsNullSafe(t *testing.T) {
	assert.Empty(t, cipherCollectionIDs(vaultwardenCipher{}))
	assert.Equal(t, []string{"c1"}, cipherCollectionIDs(vaultwardenCipher{CollectionIDs: []string{"c1"}}))
}
