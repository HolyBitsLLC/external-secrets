[Vaultwarden](https://github.com/dani-garcia/vaultwarden) is a lightweight,
Bitwarden-compatible server. ESO authenticates to it with a personal API key and
decrypts vault items locally, so reading a secret requires the account's master
password in addition to the API key credentials.

## Store configuration

The provider needs three values from the same Vaultwarden account: the
`client_id` and `client_secret` of a personal API key (created in the web vault
under *Settings* → *Security* → *Keys* → *API key*) and the account's master
password. Put them in a Kubernetes Secret and reference the keys from the
SecretStore:

```yaml
{% include 'vaultwarden-secret-store.yaml' %}
```

Decryption happens in the controller: the master password unlocks the account
symmetric key, which decrypts the items. Anyone who can read that Secret and the
SecretStore can read the whole vault the account has access to, so scope the
service account and the Secret accordingly.

### Organization scope

By default the store reads the account's personal vault. Setting
`organizationId` or `organizationName` scopes every read and write to a single
organization instead:

```yaml
{% include 'vaultwarden-secret-store-organization.yaml' %}
```

- `organizationId` takes the organization UUID.
- `organizationName` takes the human-readable name and is resolved to a UUID
  when the store is validated. If zero or more than one organization the account
  belongs to match, the store fails validation rather than guessing.

The two fields are mutually exclusive.

### Collection scope

`collectionId` or `collectionName` narrows an organization-scoped store to a
single collection. Use it when the same item name exists in several collections
of the organization. Both require an organization scope — collections do not
exist in the personal vault — and are mutually exclusive. A `collectionName`
that matches zero or more than one collection is an error.

### Custom CA certificate

If Vaultwarden uses a certificate signed by a private CA, supply the
PEM-encoded bundle inline via `caBundle` or reference a Secret/ConfigMap via
`caProvider`. When neither is set, the system root certificates are used. TLS
verification cannot be disabled.

```yaml
{% include 'vaultwarden-secret-store-ca.yaml' %}
```

### Caching

Reads can be cached client-side. Caching is disabled unless `cache` is set,
because a cached value is stale until its TTL expires and that is only safe when
the TTL is shorter than the `refreshInterval` of every ExternalSecret that uses
the store.

```yaml
{% include 'vaultwarden-secret-store-cache.yaml' %}
```

The cache belongs to a store version: editing the store, or setting the
`external-secrets.io/force-sync` annotation on it, discards it. Writes through a
PushSecret invalidate the item they touch.

## Creating an ExternalSecret

`remoteRef.key` names the vault item, either by its name or by its item UUID.
Without a `property`, the value is the item's primary field: the password of a
login item, the private key of an SSH-key item, or the notes of a secure note.

```yaml
{% include 'vaultwarden-external-secret.yaml' %}
```

`remoteRef.property` selects a single value. It is resolved in this order:

1. a custom field whose name matches, e.g. `property: api-token`;
2. a structural property of the item type — `username` and `password` for logins,
   `privateKey`, `publicKey` and `keyFingerprint` for SSH keys;
3. a key inside the item's notes when the notes hold a JSON object;
4. an attachment, matched by filename or by attachment UUID.

Item names are matched after decryption. A name that matches more than one item
is an error: the provider never silently picks one. Address the intended item by
UUID in that case.

### Finding items by name

`dataFrom` with `find.name.regexp` returns all matching items as a name/value
map, using the primary value of each item.

```yaml
{% include 'vaultwarden-external-secret-find.yaml' %}
```

## Pushing secrets

The provider is read-write. A PushSecret stores the pushed data as a secure note
whose notes hold the data as a JSON object, so it can be read back with
`GetSecretMap` or with `property` naming one of its keys.

```yaml
{% include 'vaultwarden-push-secret.yaml' %}
```

When the store is organization-scoped, pushed items are encrypted with the
organization key and created inside the organization. Deleting through a
PushSecret removes the matching item; a delete that would match more than one
item is refused.
