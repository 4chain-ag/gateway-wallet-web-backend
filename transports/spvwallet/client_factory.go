package spvwallet

import (
	overlayApi "github.com/4chain-AG/gateway-overlay/pkg/open_api"
	"github.com/bitcoin-sv/spv-wallet-web-backend/domain/users"
	"github.com/rs/zerolog"
)

type walletClientFactory struct {
	log               *zerolog.Logger
	overlay           *overlayApi.Client
	overlayAPIVersion APIVersion
}

// NewWalletClientFactory implements the ClientFactory.
func NewWalletClientFactory(log *zerolog.Logger, overlay *overlayApi.Client, overlayAPIVersion APIVersion) users.WalletClientFactory {
	logger := log.With().Str("service", "spv-wallet-client").Logger()
	return &walletClientFactory{
		log:               &logger,
		overlay:           overlay,
		overlayAPIVersion: overlayAPIVersion,
	}
}

// CreateAdminClient returns AdminWalletClient as spv-wallet-go-client instance with admin key.
func (bf *walletClientFactory) CreateAdminClient() (users.AdminWalletClient, error) {
	return newAdminClientAdapter(bf.log)
}

// CreateWithXpriv returns UserWalletClient as spv-wallet-go-client instance with given xpriv.
func (bf *walletClientFactory) CreateWithXpriv(xpriv string) (users.UserWalletClient, error) {
	return newUserClientAdapterWithXPriv(bf.log, xpriv, bf.overlay, bf.overlayAPIVersion)
}

// CreateWithAccessKey returns UserWalletClient as spv-wallet-go-client instance with given access key.
func (bf *walletClientFactory) CreateWithAccessKey(accessKey string) (users.UserWalletClient, error) {
	return newUserClientAdapterWithAccessKey(bf.log, accessKey, bf.overlay, bf.overlayAPIVersion)
}
