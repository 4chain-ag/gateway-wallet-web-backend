package transactions

import (
	"context"
	"fmt"
	"math"
	"time"

	tokenengine "github.com/4chain-AG/gateway-overlay/pkg/token_engine"
	"github.com/4chain-AG/gateway-overlay/pkg/token_engine/bsv21"
	"github.com/avast/retry-go/v4"
	"github.com/bitcoin-sv/spv-wallet-go-client/commands"
	"github.com/bitcoin-sv/spv-wallet-web-backend/domain/users"
	"github.com/bitcoin-sv/spv-wallet-web-backend/notification"
	"github.com/bitcoin-sv/spv-wallet-web-backend/spverrors"
	"github.com/bitcoin-sv/spv-wallet/models"
	"github.com/bitcoin-sv/spv-wallet/models/filter"
	"github.com/rs/zerolog"
)

const (
	satoshisNeededForTransfer = 2
	satoshiUnit               = "sat"
)

// TransactionService represents service whoch contains methods linked with transactions.
type TransactionService struct {
	adminWalletClient   users.AdminWalletClient
	walletClientFactory users.WalletClientFactory
	log                 *zerolog.Logger
}

// NewTransactionService creates new transaction service.
func NewTransactionService(adminWalletClient users.AdminWalletClient, walletClientFactory users.WalletClientFactory, log *zerolog.Logger) *TransactionService {
	transactionServiceLogger := log.With().Str("service", "transaction-service").Logger()
	return &TransactionService{
		adminWalletClient:   adminWalletClient,
		walletClientFactory: walletClientFactory,
		log:                 &transactionServiceLogger,
	}
}

// CreateTransaction creates transaction.
func (s *TransactionService) CreateTransaction(userPaymail, xpriv, recipient, unit string, amount uint64, events chan notification.TransactionEvent) error {
	userWalletClient, err := s.walletClientFactory.CreateWithXpriv(xpriv)
	if err != nil {
		return spverrors.ErrCreateTransaction.Wrap(err)
	}

	var draftTransaction users.DraftTransaction
	metadata := map[string]any{"receiver": recipient, "sender": userPaymail}

	if unit == satoshiUnit {
		recipients := []*commands.Recipients{{Satoshis: amount, To: recipient}}
		draftTransaction, err = userWalletClient.CreateAndFinalizeTransaction(recipients, metadata)
		if err != nil {
			s.log.Debug().Msgf("Error during create transaction: %s", err.Error())
			return spverrors.ErrCreateTransaction
		}
	} else {
		draftTransaction, err = s.prepareTokenTransaction(userWalletClient, userPaymail, xpriv, recipient, unit, amount, metadata)
		if err != nil {
			return err
		}
	}

	go func() {
		if err == nil {
			return
		}

		tx, err := tryRecordTransaction(userWalletClient, draftTransaction, metadata, s.log)
		if err != nil {
			events <- notification.PrepareTransactionErrorEvent(err)
		} else if tx != nil {
			events <- notification.PrepareTransactionEvent(tx)
		}
	}()

	return nil
}

func (s *TransactionService) prepareTokenTransaction(walletClient users.UserWalletClient, userPaymail, xpriv, recipient, unit string, amount uint64, metadata map[string]any) (users.DraftTransaction, error) {
	utxos, err := walletClient.GetUTXOs(context.Background())
	if err != nil {
		s.log.Error().Msgf("Error while getting utxos: %v", err.Error())
		return nil, spverrors.ErrGetXPub
	}

	tokenUtxos, tokenAmount, err := tokenengine.GetBsv21Utxos(unit, utxos, amount)
	if err != nil {
		if err == tokenengine.ErrNotEnoughTokenUTXOs {
			return nil, spverrors.ErrNotEnoughTokenUTXOs
		}
		return nil, err
	}

	satAmount := uint64(satoshisNeededForTransfer)
	changeAmount := uint64(0)
	if tokenAmount > amount {
		// we need one more sat for token change
		satAmount++
		changeAmount = tokenAmount - amount
	}

	feeUtxos, err := tokenengine.GetClassicUtxos(utxos, satAmount)
	if err != nil {
		if err == tokenengine.ErrNotEnoughUTXOs {
			return nil, spverrors.ErrNotEnoughUTXOs
		}
		return nil, err
	}

	sendScript, err := bsv21.NewBsv21Transfer(unit, amount)
	if err != nil {
		return nil, fmt.Errorf("failed preparing token transfer inscription: %w", err)
	}

	tokenTransfer := &users.TokenOutput{To: recipient, Script: sendScript.String()}

	var tokenChange *users.TokenOutput
	if changeAmount > 0 {
		tokenChangeScript, err := bsv21.NewBsv21Transfer(unit, changeAmount)
		if err != nil {
			return nil, fmt.Errorf("failed preparing token transfer inscription: %w", err)
		}
		tokenChange = &users.TokenOutput{To: userPaymail, Script: tokenChangeScript.String()}
	}

	draftTransaction, err := walletClient.DraftAndSignTokenTransaction(tokenTransfer, tokenChange, append(tokenUtxos, feeUtxos...), xpriv, metadata)
	if err != nil {
		s.log.Debug().Msgf("Error during create transaction: %s", err.Error())
		return nil, spverrors.ErrCreateTransaction
	}

	return draftTransaction, nil
}

// GetTransaction returns transaction by id.
func (s *TransactionService) GetTransaction(accessKey, id, userPaymail string) (users.FullTransaction, error) {
	// Try to generate user-client with decrypted xpriv.
	userWalletClient, err := s.walletClientFactory.CreateWithAccessKey(accessKey)
	if err != nil {
		return nil, spverrors.ErrGetTransaction.Wrap(err)
	}

	transaction, err := userWalletClient.GetTransaction(id, userPaymail)
	if err != nil {
		s.log.Debug().Msgf("Error during get transaction: %s", err.Error())
		return nil, spverrors.ErrGetTransaction
	}

	return transaction, nil
}

// GetTransactions returns transactions by access key.
func (s *TransactionService) GetTransactions(accessKey, userPaymail string, queryParam *filter.QueryParams) (*PaginatedTransactions, error) {
	// Try to generate user-client with decrypted xpriv.
	userWalletClient, err := s.walletClientFactory.CreateWithAccessKey(accessKey)
	if err != nil {
		return nil, spverrors.ErrGetTransactions.Wrap(err)
	}

	count, err := userWalletClient.GetTransactionsCount()
	if err != nil {
		s.log.Debug().Msgf("Error during get transactions count: %s", err.Error())
		return nil, spverrors.ErrGetTransactions.Wrap(err)
	}

	transactions, err := userWalletClient.GetTransactions(queryParam, userPaymail)
	if err != nil {
		s.log.Debug().Msgf("Error during get transactions: %s", err.Error())
		return nil, spverrors.ErrGetTransactions.Wrap(err)
	}

	// Calculate pages.
	pages := int(math.Ceil(float64(count) / float64(queryParam.PageSize)))

	pTransactions := &PaginatedTransactions{
		Count:        count,
		Pages:        pages,
		Transactions: transactions,
	}

	return pTransactions, nil
}

func tryRecordTransaction(userWalletClient users.UserWalletClient, draftTx users.DraftTransaction, metadata map[string]any, log *zerolog.Logger) (*models.Transaction, error) {
	retries := uint(3)
	tx, recordErr := tryRecord(userWalletClient, draftTx, metadata, log, retries)

	if recordErr != nil {
		log.Error().
			Str("draftTxID", draftTx.GetDraftTransactionID()).
			Msgf("record transaction failed: %s", recordErr.Error())
		return nil, spverrors.ErrRecordTransaction
	}

	log.Debug().
		Str("draftTxID", draftTx.GetDraftTransactionID()).
		Msg("transaction successfully recorded")
	return tx, nil
}

func tryRecord(userWalletClient users.UserWalletClient, draftTx users.DraftTransaction, metadata map[string]any, log *zerolog.Logger, retries uint) (*models.Transaction, error) {
	log.Debug().
		Str("draftTxID", draftTx.GetDraftTransactionID()).
		Msg("record transaction")

	tx := &models.Transaction{}
	err := retry.Do(
		func() error {
			var err error
			tx, err = userWalletClient.RecordTransaction(draftTx.GetDraftTransactionHex(), draftTx.GetDraftTransactionID(), metadata)
			return err //nolint:wrapcheck // error wrapped higher in call stack
		},
		retry.Attempts(retries),
		retry.Delay(1*time.Second),
		retry.OnRetry(func(n uint, err error) {
			log.Warn().
				Str("draftTxID", draftTx.GetDraftTransactionID()).
				Msgf("%d retry RecordTransaction after error: %v", n, err.Error())
		}),
	)
	return tx, err //nolint:wrapcheck // error wrapped higher in call stack
}
