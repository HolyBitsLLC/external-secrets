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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/runtime/cache"
)

func newStore(provider *esv1.VaultwardenProvider) *esv1.SecretStore {
	return &esv1.SecretStore{
		Spec: esv1.SecretStoreSpec{
			Provider: &esv1.SecretStoreProvider{Vaultwarden: provider},
		},
	}
}

func TestValidateStore_OrgXOR(t *testing.T) {
	p := &Provider{}
	cases := []struct {
		name    string
		orgID   string
		orgName string
		wantErr bool
	}{
		{"both empty - personal scope OK", "", "", false},
		{"id only - OK", "af061424-2700-425a-8800-80e988194e8e", "", false},
		{"name only - OK", "", "Tiberius-Grail", false},
		{"both set - rejected", "af061424-2700-425a-8800-80e988194e8e", "Tiberius-Grail", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &esv1.VaultwardenProvider{
				URL:              "https://vault.example.com",
				OrganizationID:   tc.orgID,
				OrganizationName: tc.orgName,
			}
			_, err := p.ValidateStore(newStore(provider))
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateStore_CollectionScope(t *testing.T) {
	const org = "af061424-2700-425a-8800-80e988194e8e"

	cases := []struct {
		name    string
		orgID   string
		orgName string
		collID  string
		collNam string
		wantErr string
	}{
		{
			name:  "collection id with org id is accepted",
			orgID: org, collID: "coll-1",
		},
		{
			name:    "collection name with org name is accepted",
			orgName: "Tiberius-Grail", collNam: "platform",
		},
		{
			name:  "collection id and name together are rejected",
			orgID: org, collID: "coll-1", collNam: "platform",
			wantErr: "mutually exclusive",
		},
		{
			name:    "collection scope without an org scope is rejected",
			collNam: "platform",
			wantErr: "require organizationId or organizationName",
		},
		{
			name:  "no collection scope is accepted",
			orgID: org,
		},
	}

	p := &Provider{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &esv1.VaultwardenProvider{
				URL:              "https://vault.example.com",
				OrganizationID:   tc.orgID,
				OrganizationName: tc.orgName,
				CollectionID:     tc.collID,
				CollectionName:   tc.collNam,
			}
			_, err := p.ValidateStore(newStore(provider))
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestValidateStore_CacheBounds(t *testing.T) {
	p := &Provider{}
	cases := []struct {
		name    string
		cache   *esv1.CacheConfig
		wantErr string
	}{
		{
			name:  "unset cache is accepted (caching disabled)",
			cache: nil,
		},
		{
			name:  "empty cache is accepted and takes the defaults",
			cache: &esv1.CacheConfig{},
		},
		{
			name:  "explicit bounds are accepted",
			cache: cacheConfig(time.Minute, 10),
		},
		{
			name:    "negative max size is rejected",
			cache:   &esv1.CacheConfig{MaxSize: -1},
			wantErr: "maxSize must not be negative",
		},
		{
			name:    "negative ttl is rejected",
			cache:   &esv1.CacheConfig{TTL: metav1.Duration{Duration: -time.Second}},
			wantErr: "ttl must not be negative",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := p.ValidateStore(newStore(&esv1.VaultwardenProvider{
				URL:   "https://vault.example.com",
				Cache: tc.cache,
			}))
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// TestNewSecretCacheDefaults pins the defaults applied for `cache: {}`.
func TestNewSecretCacheDefaults(t *testing.T) {
	lru := newSecretCache(&esv1.CacheConfig{})
	require.NotNil(t, lru)
	lru.Add("k", []byte("v"))
	if _, ok := lru.Get("k"); !ok {
		t.Fatal("an entry added to the default cache must be retrievable")
	}
	assert.Nil(t, newSecretCache(nil), "an unset cache spec must not create a cache")
}

// storeForCache builds a store with a stable identity so provider-cache keys are
// predictable.
func storeForCache(name, namespace, resourceVersion string, annotations map[string]string) *esv1.SecretStore {
	s := newStore(&esv1.VaultwardenProvider{URL: "https://vault.example.com"})
	s.Name = name
	s.Namespace = namespace
	s.ResourceVersion = resourceVersion
	s.Annotations = annotations
	return s
}

// TestProviderClientCacheReusesClientPerStoreVersion is the mechanism behind the
// refresh control: an unchanged store reuses its client (and therefore its value
// cache and auth token), and any store edit rebuilds it from scratch.
func TestProviderClientCacheReusesClientPerStoreVersion(t *testing.T) {
	ctx := context.Background()
	p := &Provider{clientCache: newClientCache()}
	store := storeForCache("vw", "external-secrets", "1", nil)

	first, err := p.NewClient(ctx, store, nil, store.Namespace)
	require.NoError(t, err)
	second, err := p.NewClient(ctx, store, nil, store.Namespace)
	require.NoError(t, err)
	assert.Same(t, first, second, "an unchanged store must reuse its client")

	store.ResourceVersion = "2"
	third, err := p.NewClient(ctx, store, nil, store.Namespace)
	require.NoError(t, err)
	assert.NotSame(t, first, third, "a store edit must rebuild the client")
}

// TestProviderClientCacheForceSyncAnnotationIsTheRefreshControl verifies the
// declared control: changing the external-secrets.io/force-sync annotation on the
// store invalidates the cached client even though API-server semantics would
// already bump the resourceVersion — the version string carries it explicitly so
// the control cannot silently stop working.
func TestProviderClientCacheForceSyncAnnotationIsTheRefreshControl(t *testing.T) {
	ctx := context.Background()
	p := &Provider{clientCache: newClientCache()}
	store := storeForCache("vw", "external-secrets", "7", map[string]string{esv1.AnnotationForceSync: "v1"})

	before, err := p.NewClient(ctx, store, nil, store.Namespace)
	require.NoError(t, err)

	// Same resourceVersion, new annotation value: the version must still differ.
	store.Annotations = map[string]string{esv1.AnnotationForceSync: "v2"}
	after, err := p.NewClient(ctx, store, nil, store.Namespace)
	require.NoError(t, err)
	assert.NotSame(t, before, after, "the force-sync annotation must invalidate the cached client")

	// And an unchanged annotation+RV reuses again.
	again, err := p.NewClient(ctx, store, nil, store.Namespace)
	require.NoError(t, err)
	assert.Same(t, after, again)
}

// TestProviderClientCacheDistinctStoresAreDistinctEntries proves two stores
// cannot share a client (and therefore cannot share a value cache).
func TestProviderClientCacheDistinctStoresAreDistinctEntries(t *testing.T) {
	ctx := context.Background()
	p := &Provider{clientCache: newClientCache()}

	a, err := p.NewClient(ctx, storeForCache("store-a", "external-secrets", "1", nil), nil, "external-secrets")
	require.NoError(t, err)
	b, err := p.NewClient(ctx, storeForCache("store-b", "external-secrets", "1", nil), nil, "external-secrets")
	require.NoError(t, err)
	assert.NotSame(t, a, b)
}

// TestClientCacheCleanupPurgesSecretCache covers the eviction edge directly.
func TestClientCacheCleanupPurgesSecretCache(t *testing.T) {
	cached := &Client{secretCache: newSecretCache(cacheConfig(time.Minute, 8))}
	buf := []byte("decrypted-material")
	cached.secretCache.Add(secretCacheKey("item", cacheKindSecret, ""), buf)

	clientCacheCleanup(cached)

	assert.Equal(t, make([]byte, len("decrypted-material")), buf)
	assert.Equal(t, 0, cached.secretCache.Len())
}

// TestClientCacheEvictionWiring proves the cleanup is actually wired into the
// cache implementation, not just callable.
func TestClientCacheEvictionWiring(t *testing.T) {
	small := cache.Must[esv1.SecretsClient](1, clientCacheCleanup)
	first := &Client{secretCache: newSecretCache(cacheConfig(time.Minute, 8))}
	buf := []byte("first-secret")
	first.secretCache.Add(secretCacheKey("item", cacheKindSecret, ""), buf)

	small.Add("1", cache.Key{Name: "a", Namespace: "ns"}, first)
	small.Add("1", cache.Key{Name: "b", Namespace: "ns"}, &Client{secretCache: newSecretCache(cacheConfig(time.Minute, 8))})

	assert.Equal(t, make([]byte, len("first-secret")), buf, "the evicted client's cache must be zeroed")
}

// TestProviderWithoutCacheStillBuildsAClient proves a zero-valued Provider (as
// constructed in unit tests) degrades to no caching instead of panicking.
func TestProviderWithoutCacheStillBuildsAClient(t *testing.T) {
	p := &Provider{}
	client, err := p.NewClient(context.Background(), storeForCache("vw", "ns", "1", nil), nil, "ns")
	require.NoError(t, err)
	require.NotNil(t, client)

	again, err := p.NewClient(context.Background(), storeForCache("vw", "ns", "1", nil), nil, "ns")
	require.NoError(t, err)
	assert.NotSame(t, client, again, "a provider with no cache cannot reuse clients")
}
