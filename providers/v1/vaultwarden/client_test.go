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

import "testing"

func TestFilterCiphersByScope(t *testing.T) {
	ciphers := []vaultwardenCipher{
		{ID: "p1", Type: 1, OrganizationID: nil},                                            // personal Login
		{ID: "p2", Type: 2, OrganizationID: nil},                                            // personal SecureNote
		{ID: "o1", Type: 1, OrganizationID: "uuid-a"},                                       // org A Login
		{ID: "o2", Type: 2, OrganizationID: "uuid-b"},                                       // org B SecureNote
		{ID: "deleted", Type: 1, OrganizationID: nil, DeletedDate: "2026-01-01T00:00:00Z"},  // deleted
		{ID: "unsupported", Type: 5, OrganizationID: nil},                                   // not Login or SecureNote
	}

	// Personal scope: only p1, p2 (no deleted, no unsupported type).
	got := filterCiphersByScope(ciphers, "")
	gotIDs := cipherIDs(got)
	if !equalStringSlice(gotIDs, []string{"p1", "p2"}) {
		t.Fatalf("personal scope: got %v want [p1 p2]", gotIDs)
	}

	// Org A scope: only o1.
	got = filterCiphersByScope(ciphers, "uuid-a")
	gotIDs = cipherIDs(got)
	if !equalStringSlice(gotIDs, []string{"o1"}) {
		t.Fatalf("org-a scope: got %v want [o1]", gotIDs)
	}
}

func cipherIDs(cs []vaultwardenCipher) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.ID)
	}
	return out
}

func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
