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
	"fmt"
	"sort"
	"strings"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

// collectionEntry is one organization collection as returned by GET /api/sync.
// Vaultwarden returns the collections the authenticated user can access, each
// tagged with the organization it belongs to.
type collectionEntry struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organizationId"`
	Name           string `json:"name"`
}

// cipherCollectionIDs normalizes a cipher's collectionIds field. Vaultwarden
// sends `null` for personal items and an array of UUIDs for org items.
func cipherCollectionIDs(c vaultwardenCipher) []string {
	return c.CollectionIDs
}

// filterCiphersByCollection narrows a cipher set to those that belong to
// collectionID. An empty collectionID is a no-op, so callers that configure no
// collection keep today's org-wide (or personal) behaviour.
func filterCiphersByCollection(ciphers []vaultwardenCipher, collectionID string) []vaultwardenCipher {
	if collectionID == "" {
		return ciphers
	}
	out := make([]vaultwardenCipher, 0, len(ciphers))
	for _, c := range ciphers {
		for _, id := range cipherCollectionIDs(c) {
			if id == collectionID {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

// resolveCollectionID converts the store's collection scope into a collection
// UUID. It returns "" when no collection scope is configured.
//
// Discipline mirrors resolveOrgByName: an explicit id must exist in the org, and
// a name must match exactly one collection *within the resolved organization*.
// Zero matches and ambiguous matches are hard errors — a name that resolves to
// more than one collection must never silently pick one, because that is the
// ambiguous-reference class that has repeatedly broken this estate.
//
// orgID is the org the ciphers are already scoped to ("" for personal scope).
// Collections are organization-scoped in Vaultwarden, so a collection scope
// without an org scope is a configuration error rejected by ValidateStore; the
// check is repeated here so the provider cannot be driven into that state by a
// store that bypassed admission validation.
func resolveCollectionID(collections []collectionEntry, provider *esv1.VaultwardenProvider, orgID string) (string, error) {
	wantID := provider.CollectionID
	wantName := provider.CollectionName
	if wantID == "" && wantName == "" {
		return "", nil
	}
	if orgID == "" {
		return "", fmt.Errorf("vaultwarden: collectionId/collectionName require an organization scope; set organizationId or organizationName")
	}

	inOrg := make([]collectionEntry, 0, len(collections))
	for _, c := range collections {
		if c.OrganizationID == orgID {
			inOrg = append(inOrg, c)
		}
	}

	if wantID != "" {
		for _, c := range inOrg {
			if c.ID == wantID {
				return c.ID, nil
			}
		}
		return "", fmt.Errorf("vaultwarden: collectionId %q not found in organization %q", wantID, orgID)
	}

	matches := make([]collectionEntry, 0, 1)
	for _, c := range inOrg {
		if c.Name == wantName {
			matches = append(matches, c)
		}
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("vaultwarden: no collection named %q in organization %q", wantName, orgID)
	case 1:
		return matches[0].ID, nil
	default:
		return "", fmt.Errorf("vaultwarden: more than one collection named %q in organization %q (candidates: %s); use collectionId instead",
			wantName, orgID, strings.Join(collectionIDs(matches), ", "))
	}
}

// collectionIDs returns the ids of the given collections, sorted for stable
// error messages in tests.
func collectionIDs(collections []collectionEntry) []string {
	out := make([]string, 0, len(collections))
	for _, c := range collections {
		out = append(out, c.ID)
	}
	sort.Strings(out)
	return out
}
