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

// Package vaultwarden implements a provider for syncing secrets from a self-hosted Vaultwarden instance.
package vaultwarden

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/runtime/esutils"
)

const errUnexpectedStoreSpec = "unexpected store spec"

// Provider implements esv1.Provider for Vaultwarden.
type Provider struct{}

var _ esv1.Provider = &Provider{}

// Capabilities returns ReadWrite.
func (p *Provider) Capabilities() esv1.SecretStoreCapabilities {
	return esv1.SecretStoreReadWrite
}

// NewClient constructs a new secrets client based on the provided store.
func (p *Provider) NewClient(ctx context.Context, store esv1.GenericStore, kube client.Client, namespace string) (esv1.SecretsClient, error) {
	prov, err := getProvider(store)
	if err != nil {
		return nil, err
	}
	c := &Client{
		provider:  prov,
		crClient:  kube,
		namespace: namespace,
		store:     store,
	}
	// Resolve a CAProvider reference (Secret/ConfigMap) into CA bytes so
	// initHTTPClient can trust self-signed certs. CAProvider takes
	// precedence over CABundle.
	if prov.CAProvider != nil {
		caBytes, err := esutils.FetchCACertFromSource(ctx, esutils.CreateCertOpts{
			CAProvider: prov.CAProvider,
			StoreKind:  store.GetKind(),
			Namespace:  namespace,
			Client:     kube,
		})
		if err != nil {
			return nil, fmt.Errorf("vaultwarden: loading CA certificate: %w", err)
		}
		prov.CABundle = caBytes
	}
	if err := c.initHTTPClient(); err != nil {
		return nil, err
	}
	return c, nil
}

// initHTTPClient builds Client.httpClient using strict TLS verification:
// the system cert pool augmented with the provider's optional caBundle.
// MinVersion is TLS 1.2. There is no InsecureSkipVerify escape hatch —
// self-signed certs must be trusted via caBundle.
func (c *Client) initHTTPClient() error {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if len(c.provider.CABundle) > 0 {
		if !pool.AppendCertsFromPEM(c.provider.CABundle) {
			return fmt.Errorf("vaultwarden: failed to parse CABundle")
		}
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
	}
	c.httpClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       tlsConfig,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			IdleConnTimeout:       90 * time.Second,
		},
	}
	return nil
}

// ValidateStore validates the configuration of a Vaultwarden secret store.
func (p *Provider) ValidateStore(store esv1.GenericStore) (admission.Warnings, error) {
	if store == nil {
		return nil, errors.New("invalid store")
	}
	spc := store.GetSpec()
	if spc == nil || spc.Provider == nil || spc.Provider.Vaultwarden == nil {
		return nil, errors.New(errUnexpectedStoreSpec)
	}
	vw := spc.Provider.Vaultwarden
	if vw.OrganizationID != "" && vw.OrganizationName != "" {
		return admission.Warnings{}, errors.New("vaultwarden: organizationId and organizationName are mutually exclusive; set at most one")
	}
	return nil, nil
}

func NewProvider() esv1.Provider {
	return &Provider{}
}

func ProviderSpec() *esv1.SecretStoreProvider {
	return &esv1.SecretStoreProvider{
		Vaultwarden: &esv1.VaultwardenProvider{},
	}
}

func MaintenanceStatus() esv1.MaintenanceStatus {
	return esv1.MaintenanceStatusMaintained
}
