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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

// ref is a shorthand for a read reference.
func ref(key, property string) esv1.ExternalSecretDataRemoteRef {
	return esv1.ExternalSecretDataRemoteRef{Key: key, Property: property}
}

// TestGetSecretServesSecondReadFromCache is the core cache contract: with the
// cache enabled, a repeated read of the same (item, property) costs exactly one
// /api/sync instead of one per call.
func TestGetSecretServesSecondReadFromCache(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, cacheConfig(time.Minute, 8))
	fv.setCiphers(loginCipher(t, "id-1", "app", "hunter2", ""))

	first, err := c.GetSecret(ctx, ref("app", ""))
	require.NoError(t, err)
	second, err := c.GetSecret(ctx, ref("app", ""))
	require.NoError(t, err)

	assert.Equal(t, "hunter2", string(first))
	assert.Equal(t, "hunter2", string(second))
	assert.Equal(t, 1, fv.count("sync"), "second read must not hit /api/sync")
}

// TestGetSecretCacheDisabledByDefault pins the default: an unset cache spec
// caches nothing, so behaviour is unchanged for every store that does not opt
// in.
func TestGetSecretCacheDisabledByDefault(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, nil)
	fv.setCiphers(loginCipher(t, "id-1", "app", "hunter2", ""))

	for i := 0; i < 3; i++ {
		_, err := c.GetSecret(ctx, ref("app", ""))
		require.NoError(t, err)
	}
	assert.Equal(t, 3, fv.count("sync"))
}

// TestGetSecretDistinctPropertiesAreDistinctEntries verifies the property is
// part of the cache key: two fields of the same item must not collide.
func TestGetSecretDistinctPropertiesAreDistinctEntries(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, cacheConfig(time.Minute, 8))
	fv.setCiphers(fieldCipher(t, "id-1", "app", "token", "abc123"))

	got, err := c.GetSecret(ctx, ref("app", "token"))
	require.NoError(t, err)
	assert.Equal(t, "abc123", string(got))

	_, err = c.GetSecret(ctx, ref("app", "other"))
	require.Error(t, err, "a property that does not exist must still fail")
	assert.Equal(t, 2, fv.count("sync"), "a different property must not be served from the first entry")
}

// TestCacheTTLExpiryRefetches verifies that a cached value stops being served
// after its TTL, which is the bound on how stale a credential can be.
func TestCacheTTLExpiryRefetches(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, cacheConfig(100*time.Millisecond, 8))
	fv.setCiphers(loginCipher(t, "id-1", "app", "first", ""))

	got, err := c.GetSecret(ctx, ref("app", ""))
	require.NoError(t, err)
	assert.Equal(t, "first", string(got))

	// The upstream value rotates while the entry is still live: the cached copy
	// is served, which is the documented staleness window.
	fv.setCiphers(loginCipher(t, "id-1", "app", "second", ""))
	got, err = c.GetSecret(ctx, ref("app", ""))
	require.NoError(t, err)
	assert.Equal(t, "first", string(got), "within the TTL the cached value is served")
	assert.Equal(t, 1, fv.count("sync"))

	require.Eventually(t, func() bool {
		v, err := c.GetSecret(ctx, ref("app", ""))
		return err == nil && string(v) == "second"
	}, 5*time.Second, 20*time.Millisecond, "after the TTL the rotated value must be read")
	assert.GreaterOrEqual(t, fv.count("sync"), 2)
}

// TestGetSecretMapCachesWholeMap covers the map read path, which is cached as a
// single entry.
func TestGetSecretMapCachesWholeMap(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, cacheConfig(time.Minute, 8))
	fv.setCiphers(noteCipher(t, "id-1", "db", `{"username":"alice","password":"s3cr3t"}`, ""))

	first, err := c.GetSecretMap(ctx, ref("db", ""))
	require.NoError(t, err)
	second, err := c.GetSecretMap(ctx, ref("db", ""))
	require.NoError(t, err)

	assert.Equal(t, "alice", string(first["username"]))
	assert.Equal(t, "s3cr3t", string(first["password"]))
	assert.Equal(t, first, second)
	assert.Equal(t, 1, fv.count("sync"), "second map read must not hit /api/sync")
}

// TestCacheGetReturnsAnIndependentCopy verifies callers cannot corrupt the cache
// by mutating the buffer they were handed.
func TestCacheGetReturnsAnIndependentCopy(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, cacheConfig(time.Minute, 8))
	fv.setCiphers(loginCipher(t, "id-1", "app", "hunter2", ""))

	first, err := c.GetSecret(ctx, ref("app", ""))
	require.NoError(t, err)
	for i := range first {
		first[i] = 'X'
	}

	second, err := c.GetSecret(ctx, ref("app", ""))
	require.NoError(t, err)
	assert.Equal(t, "hunter2", string(second))
	assert.Equal(t, 1, fv.count("sync"))
}

// TestPushSecretInvalidatesItem verifies a write drops the cached read of the
// item it touched, so a push followed by a read cannot serve the pre-write
// value.
func TestPushSecretInvalidatesItem(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, cacheConfig(time.Minute, 8))
	fv.setCiphers(loginCipher(t, "id-1", "app", "old-value", ""))

	got, err := c.GetSecret(ctx, ref("app", ""))
	require.NoError(t, err)
	require.Equal(t, "old-value", string(got))
	require.Equal(t, 1, fv.count("sync"))

	// The push itself reads the cipher list, so it counts as a sync too.
	require.NoError(t, c.PushSecret(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "app-secret"},
		Data:       map[string][]byte{"data": []byte("new-value")},
	}, stubPushSecretData{secretKey: "data", remoteKey: "app"}))
	require.Equal(t, 1, fv.count("update"))

	// The vault now serves the pushed value; the cache must not answer for it.
	fv.setCiphers(noteCipher(t, "id-1", "app", "new-value", ""))
	after, err := c.GetSecret(ctx, ref("app", ""))
	require.NoError(t, err)
	assert.Equal(t, "new-value", string(after))
	assert.Equal(t, 3, fv.count("sync"), "the read after a write must hit /api/sync again")
}

// TestDeleteSecretInvalidatesItem is the delete half of the same contract.
func TestDeleteSecretInvalidatesItem(t *testing.T) {
	ctx := context.Background()
	c, fv := newHarness(t, cacheConfig(time.Minute, 8))
	fv.setCiphers(loginCipher(t, "id-1", "app", "hunter2", ""))

	_, err := c.GetSecret(ctx, ref("app", ""))
	require.NoError(t, err)
	require.Equal(t, 1, fv.count("sync"))

	require.NoError(t, c.DeleteSecret(ctx, stubPushSecretRemoteRef{remoteKey: "app"}))
	require.Equal(t, 1, fv.count("delete"))

	// The vault no longer serves the item; the cache must not answer for it.
	fv.setCiphers()
	_, err = c.GetSecret(ctx, ref("app", ""))
	require.Error(t, err, "the item no longer exists")
	assert.Equal(t, 3, fv.count("sync"), "the read after a delete must hit /api/sync again")
}

// TestCacheEvictionZeroesMaterial verifies that the only path where decrypted
// material leaves the cache without being read wipes it in place.
func TestCacheEvictionZeroesMaterial(t *testing.T) {
	lru := newSecretCache(cacheConfig(time.Minute, 1))

	evicted := []byte("super-secret-value")
	lru.Add(secretCacheKey("a", cacheKindSecret, ""), evicted)
	require.Contains(t, string(evicted), "super-secret")

	lru.Add(secretCacheKey("b", cacheKindSecret, ""), []byte("other"))

	assert.Equal(t, make([]byte, len("super-secret-value")), evicted, "an evicted entry must be zeroed in place")
}

// TestInvalidateItemZeroesAndRemoves verifies item-scoped invalidation wipes
// every entry for that item and leaves other items alone.
func TestInvalidateItemZeroesAndRemoves(t *testing.T) {
	c := &Client{secretCache: newSecretCache(cacheConfig(time.Minute, 8))}
	kept := []byte("keep-me")
	removed := []byte("drop-me")

	c.secretCache.Add(secretCacheKey("kept", cacheKindSecret, ""), kept)
	c.secretCache.Add(secretCacheKey("dropped", cacheKindSecret, ""), removed)

	c.invalidateItem("dropped")

	assert.Equal(t, make([]byte, len("drop-me")), removed, "invalidated material must be zeroed in place")
	assert.False(t, c.secretCache.Contains(secretCacheKey("dropped", cacheKindSecret, "")))
	assert.True(t, c.secretCache.Contains(secretCacheKey("kept", cacheKindSecret, "")))
	assert.Equal(t, []byte("keep-me"), kept, "unrelated entries must not be touched")
}

// TestPurgeSecretCacheZeroesEverything covers the provider-client-cache eviction
// path (store changed, version mismatch, LRU pressure).
func TestPurgeSecretCacheZeroesEverything(t *testing.T) {
	c := &Client{secretCache: newSecretCache(cacheConfig(time.Minute, 8))}
	first := []byte("first")
	second := []byte("second")
	c.secretCache.Add(secretCacheKey("a", cacheKindSecret, ""), first)
	c.secretCache.Add(secretCacheKey("b", cacheKindMap, ""), second)

	c.purgeSecretCache()

	assert.Equal(t, make([]byte, len("first")), first)
	assert.Equal(t, make([]byte, len("second")), second)
	assert.Equal(t, 0, c.secretCache.Len())
}

// TestPurgeSecretCacheNilSafe proves the cache-free client path is inert.
func TestPurgeSecretCacheNilSafe(t *testing.T) {
	c := &Client{}
	assert.NotPanics(t, func() {
		c.purgeSecretCache()
		c.invalidateItem("anything")
		c.cacheRemove("anything")
		_, ok := c.cacheGet("anything")
		assert.False(t, ok)
		c.cacheAdd("anything", []byte("value"))
	})
}
