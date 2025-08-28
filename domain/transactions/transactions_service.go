package transactions

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/avast/retry-go/v4"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/pkg/errors"

	tokenengine "github.com/4chain-AG/gateway-overlay/pkg/token_engine"
	"github.com/4chain-AG/gateway-overlay/pkg/token_engine/bsv21"
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
		draftTransaction, err = s.prepareClassicTransaction(userWalletClient, recipient, amount, metadata)
	} else {
		draftTransaction, err = s.prepareTokenTransaction(userWalletClient, userPaymail, xpriv, recipient, unit, amount, metadata)
	}
	if err != nil {
		return err
	}

	go func() {
		tx, err := tryRecordTransaction(userWalletClient, draftTransaction, metadata, s.log)
		if err != nil {
			events <- notification.PrepareTransactionErrorEvent(err)
		} else if tx != nil {
			events <- notification.PrepareTransactionEvent(tx)
		}
	}()

	return nil
}

func (s *TransactionService) prepareClassicTransaction(walletClient users.UserWalletClient, recipient string, amount uint64, metadata map[string]any) (users.DraftTransaction, error) {
	utxos, err := walletClient.GetUTXOs(context.Background())
	if err != nil {
		s.log.Error().Msgf("Error while getting utxos: %v", err.Error())
		return nil, spverrors.ErrGetXPub
	}

	feeUtxos, err := tokenengine.GetClassicUtxos(utxos, amount)
	if err != nil {
		if err == tokenengine.ErrNotEnoughUTXOs {
			return nil, spverrors.ErrNotEnoughUTXOs
		}
		return nil, err
	}

	draftTx, err := walletClient.DraftAndSignClassicTransaction(feeUtxos, recipient, amount, metadata)
	if err != nil {
		s.log.Debug().Msgf("Error during create transaction: %s", err.Error())
		return nil, spverrors.ErrCreateTransaction
	}

	s.log.Debug().Any("draftTx", draftTx).Msg("Classic tx")

	return draftTx, nil
}

func (s *TransactionService) prepareTokenTransaction(walletClient users.UserWalletClient, userPaymail, xpriv, recipient, tokenID string, amount uint64, metadata map[string]any) (users.DraftTransaction, error) {
	utxos, err := walletClient.GetUTXOs(context.Background())
	if err != nil {
		s.log.Error().Msgf("Error while getting utxos: %v", err.Error())
		return nil, spverrors.ErrGetXPub
	}

	// Get bsv21 tokens UTXOs
	allCoinsUtxos := tokenengine.GetAllBsv21Ttxos(utxos)
	tokenTtxos, tokenValue, err := filterCoinUtxosForCurrentStablecoinTokens(walletClient, allCoinsUtxos, amount, tokenID)
	if err != nil {
		return nil, err
	}
	if tokenValue < amount {
		return nil, tokenengine.ErrNotEnoughTokenUTXOs
	}

	outputs, outputsIndexes, changeIndexes, err := s.outputs(tokenTtxos, recipient, userPaymail, amount)
	if err != nil {
		return nil, err
	}

	// Get coin inputs for the transfer
	inputs := s.coinInputs(tokenTtxos)

	neededSatoshi := uint64(satoshisNeededForTransfer) + uint64(len(outputs))
	inputSato := uint64(len(inputs)) // I assume they're valid 1Sat

	var satoUtxos []*transaction.UTXO
	if inputSato < neededSatoshi {
		// get  missing satoshis from the operator wallet
		satoUtxos, err = tokenengine.GetClassicUtxos(utxos, neededSatoshi-inputSato)
		if err != nil {
			if errors.Is(err, tokenengine.ErrNotEnoughUTXOs) {
				return nil, spverrors.ErrNotEnoughUTXOs
			}
			return nil, err
		}
	}

	inputs = append(inputs, satoUtxos...)

	draftTransaction, err := walletClient.DraftAndSignTokenTransaction(outputs, inputs, outputsIndexes, changeIndexes, tokenID, xpriv, metadata)
	if err != nil {
		s.log.Debug().Msgf("Error during create transaction: %s", err.Error())
		return nil, spverrors.ErrCreateTransaction
	}

	s.log.Debug().Any("draftTx", draftTransaction).Msg("Token tx")
	return draftTransaction, nil
}

func (s *TransactionService) coinInputs(tokenTtxos map[bsv21.TokenID][]*tokenengine.Bsv21TTXO) []*transaction.UTXO {
	coinInputs := make([]*transaction.UTXO, 0)

	for _, ttxos := range tokenTtxos {
		for _, t := range ttxos {
			coinInputs = append(coinInputs, t.Utxo)
		}
	}

	return coinInputs
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

func (s *TransactionService) outputs(tokenUtxos map[bsv21.TokenID][]*tokenengine.Bsv21TTXO, recipient, sender string, amount uint64) ([]*users.TokenOutput, []int, []int, error) {
	outputs := make([]*users.TokenOutput, 0, len(tokenUtxos))
	outputIndexes := make([]int, 0)
	changeIndexes := make([]int, 0)

	remainingToSend := amount
	tokensForTransfer := make(map[bsv21.TokenID]uint64) // How much of each token to send
	tokensForChange := make(map[bsv21.TokenID]uint64)   // How much of each token to keep as change

	for tokenID, ttxos := range tokenUtxos {
		tokenTotal := uint64(0)
		for _, ttxo := range ttxos {
			tokenTotal += ttxo.Amount
		}

		if remainingToSend > 0 {
			if remainingToSend >= tokenTotal {
				tokensForTransfer[tokenID] = tokenTotal
				remainingToSend -= tokenTotal
			} else {
				tokensForTransfer[tokenID] = remainingToSend
				tokensForChange[tokenID] = tokenTotal - remainingToSend
				remainingToSend = 0
			}
		} else {
			tokensForChange[tokenID] = tokenTotal
		}

		if transferAmount, exists := tokensForTransfer[tokenID]; exists {
			if tokenTotal > transferAmount {
				tokensForChange[tokenID] = tokenTotal - transferAmount
			}
		}
	}

	outputIndex := 0 // This tracks the actual position in outputs array
	// Create transfer outputs
	for tokenID, amt := range tokensForTransfer {
		if amt > 0 {
			transferScript, err := bsv21.NewBsv21Transfer(tokenID, amt)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed preparing token transfer inscription: %w", err)
			}
			transfer := &users.TokenOutput{To: recipient, Script: transferScript.String()}
			outputs = append(outputs, transfer)                // Add to position outputIndex
			outputIndexes = append(outputIndexes, outputIndex) // Record this position
			outputIndex++                                      // Increment for next output
		}
	}

	// Create change outputs
	for tokenID, amt := range tokensForChange {
		if amt > 0 {
			transferScript, err := bsv21.NewBsv21Transfer(tokenID, amt)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed preparing token transfer inscription: %w", err)
			}
			changeTransfer := &users.TokenOutput{To: sender, Script: transferScript.String()}
			outputs = append(outputs, changeTransfer)          // Add to position outputIndex
			changeIndexes = append(changeIndexes, outputIndex) // Record this position
			outputIndex++                                      // Increment for next output
		}
	}

	// SPV Wallet will handle sato change automagically.
	return outputs, outputIndexes, changeIndexes, nil
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

func filterCoinUtxosForCurrentStablecoinTokens(walletClient users.UserWalletClient, allCoinUtxos map[bsv21.TokenID][]*tokenengine.Bsv21TTXO, amount uint64, stablecoinID string) (map[bsv21.TokenID][]*tokenengine.Bsv21TTXO, uint64, error) {
	filteredUtxos := make(map[bsv21.TokenID][]*tokenengine.Bsv21TTXO)
	acc := uint64(0)

	coin, err := walletClient.GetStablecoinWithSeries(context.Background(), stablecoinID)
	if err != nil {
		return nil, 0, err
	}
	series := []string{*coin.AssetId}
	if coin.Series != nil {
		series = *coin.Series
	}

	for _, tokenID := range series {
		// check if allCoinsUtxos contain stablecoin token series
		ttxos, ok := allCoinUtxos[bsv21.TokenID(tokenID)]
		if !ok {
			continue
		}

		group, found := filteredUtxos[bsv21.TokenID(tokenID)]
		if !found {
			group = make([]*tokenengine.Bsv21TTXO, 0)
		}

		for _, utxo := range ttxos {
			group = append(group, utxo)
			acc += utxo.Amount
			if acc >= amount {
				// enough tokens
				break
			}
		}

		filteredUtxos[bsv21.TokenID(tokenID)] = group
	}

	return filteredUtxos, acc, nil
}
