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
	"encoding/json"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/runtime/cache"
)

// cache defaults, matching the spec markers on esv1.CacheConfig.
const (
	defaultCacheTTL     = 5 * time.Minute
	defaultCacheMaxSize = 100
)

// Cache entry kinds. They are part of the cache key so that a GetSecret and a
// GetSecretMap for the same item can never collide.
const (
	cacheKindSecret = "secret"
	cacheKindMap    = "map"
)

// cacheKeySep separates the fields of a cache key. NUL cannot appear in a
// Vaultwarden item name, property name, or cipher UUID, so it is unambiguous.
const cacheKeySep = "\x00"

// cacheVersion is the version string the provider client cache is keyed on.
//
// It is the store's resourceVersion — so *any* edit to the store (spec or
// metadata) drops the cached client and with it the cached secret values —
// combined with the value of the declared refresh control, the
// `external-secrets.io/force-sync` annotation (esv1.AnnotationForceSync, the
// same constant ESO core documents for manually refreshing an ExternalSecret).
//
// Namely: a store-scoped force-sync annotation is the explicit, declarative
// cache-refresh control. Touching it changes the version and therefore
// guarantees a miss even if the resourceVersion were ever reused.
func cacheVersion(store esv1.GenericStore) string {
	meta := store.GetObjectMeta()
	rv := meta.GetResourceVersion()
	if ann := meta.GetAnnotations(); ann != nil {
		if v, ok := ann[esv1.AnnotationForceSync]; ok {
			return rv + "|" + esv1.AnnotationForceSync + "=" + v
		}
	}
	return rv
}

// clientCacheCleanup runs when a Client is dropped from the provider client
// cache — a store edit, a version mismatch, or LRU pressure. The client's cached
// plaintext must not outlive the store configuration it was read under, so it is
// zeroed here rather than left to the GC.
func clientCacheCleanup(client esv1.SecretsClient) {
	if vw, ok := client.(*Client); ok {
		vw.purgeSecretCache()
	}
}

// newClientCache builds the provider-level client cache.
func newClientCache() *cache.Cache[esv1.SecretsClient] {
	return cache.Must[esv1.SecretsClient](100, clientCacheCleanup)
}

// newSecretCache builds the per-client value cache, or returns nil when the
// store does not opt in. Caching is disabled by default: a cached value is
// stale for up to its TTL, and that only stays safe while the TTL is shorter
// than every consuming ExternalSecret's refreshInterval.
//
// Known limitation inherited from golang-lru/v2 v2.0.7: an expirable LRU starts
// an expiry goroutine that cannot be stopped (LRU.Close is commented out in the
// dependency), so each Client that enables the cache leaves one goroutine
// behind. Clients only churn when their store changes, and the provider client
// cache is bounded, so the exposure is a handful of goroutines per store edit —
// the same shape as the 1Password SDK provider, which uses the same primitive.
func newSecretCache(cfg *esv1.CacheConfig) *lru.LRU[string, []byte] {
	if cfg == nil {
		return nil
	}
	ttl := defaultCacheTTL
	if cfg.TTL.Duration > 0 {
		ttl = cfg.TTL.Duration
	}
	maxSize := defaultCacheMaxSize
	if cfg.MaxSize > 0 {
		maxSize = cfg.MaxSize
	}
	// The eviction callback is the only place decrypted material leaves the
	// cache without being read, so it must zero the buffer in place.
	return lru.NewLRU[string, []byte](maxSize, func(_ string, value []byte) {
		zeroBytes(value)
	}, ttl)
}

// secretCacheKey builds a key from the resolved scope (item + entry kind +
// property).
//
// Store identity and org/collection scope are deliberately NOT in the key: the
// cache belongs to a Client, and a Client belongs to exactly one store at one
// store version (see Provider.NewClient). Changing the store spec — including
// its org or collection scope — changes the resourceVersion, which swaps the
// whole Client and its cache, so cross-store or cross-scope reuse is
// structurally impossible rather than merely avoided.
//
// The item is first so that every entry for one item can be invalidated by
// prefix when that item is written or deleted.
func secretCacheKey(item, kind, property string) string {
	return item + cacheKeySep + kind + cacheKeySep + property
}

// cacheGet returns a copy of a cached value. Callers receive their own buffer so
// that an eviction (which zeroes the cached buffer) can never mutate the bytes
// an ExternalSecret is concurrently being built from.
func (c *Client) cacheGet(key string) ([]byte, bool) {
	if c.secretCache == nil {
		return nil, false
	}
	v, ok := c.secretCache.Get(key)
	if !ok {
		return nil, false
	}
	return bytes.Clone(v), true
}

// cacheAdd stores a copy of value. No-op when caching is disabled.
func (c *Client) cacheAdd(key string, value []byte) {
	if c.secretCache == nil {
		return
	}
	c.secretCache.Add(key, bytes.Clone(value))
}

// cacheGetMap is the GetSecretMap counterpart of cacheGet. Whole maps are cached
// as JSON under the (item, cacheKindMap, "") key, so a map read costs one
// /api/sync on the first call and nothing afterwards until the entry expires.
func (c *Client) cacheGetMap(key string) (map[string][]byte, bool) {
	raw, ok := c.cacheGet(key)
	if !ok {
		return nil, false
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &decoded); err != nil {
		// A cache entry we cannot decode is treated as a miss; drop it rather
		// than re-decoding it on every call.
		c.cacheRemove(key)
		return nil, false
	}
	out := make(map[string][]byte, len(decoded))
	for k, v := range decoded {
		out[k] = jsonRawToBytes(v)
	}
	return out, true
}

// cacheAddMap stores a whole GetSecretMap result. Values are JSON-encoded so the
// round trip is lossless and key order does not matter.
func (c *Client) cacheAddMap(key string, value map[string][]byte) {
	if c.secretCache == nil {
		return
	}
	encoded := make(map[string]json.RawMessage, len(value))
	for k, v := range value {
		if json.Valid(v) {
			encoded[k] = json.RawMessage(v)
			continue
		}
		// Not valid JSON on its own: store it as a JSON string so the map
		// survives the round trip unchanged.
		b, err := json.Marshal(string(v))
		if err != nil {
			return
		}
		encoded[k] = json.RawMessage(b)
	}
	raw, err := json.Marshal(encoded)
	if err != nil {
		return
	}
	c.cacheAdd(key, raw)
}

// cacheRemove drops one entry, zeroing it first.
func (c *Client) cacheRemove(key string) {
	if c.secretCache == nil {
		return
	}
	if v, ok := c.secretCache.Peek(key); ok {
		zeroBytes(v)
	}
	c.secretCache.Remove(key)
}

// invalidateItem drops every cached entry for one item. Called after any write
// to that item so a PushSecret followed by a read in the same window cannot
// serve the pre-write value.
func (c *Client) invalidateItem(item string) {
	if c.secretCache == nil {
		return
	}
	prefix := item + cacheKeySep
	for _, key := range c.secretCache.Keys() {
		if strings.HasPrefix(key, prefix) {
			c.cacheRemove(key)
		}
	}
}

// purgeSecretCache zeroes and drops every cached entry. Called when the client
// itself is evicted from the provider client cache, i.e. when the store it
// belongs to changed.
func (c *Client) purgeSecretCache() {
	if c.secretCache == nil {
		return
	}
	for _, key := range c.secretCache.Keys() {
		if v, ok := c.secretCache.Peek(key); ok {
			zeroBytes(v)
		}
	}
	c.secretCache.Purge()
}
