package spvwallet

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	walletclient "github.com/bitcoin-sv/spv-wallet-go-client"
	"github.com/bitcoin-sv/spv-wallet-go-client/commands"
	walletclientCfg "github.com/bitcoin-sv/spv-wallet-go-client/config"
	"github.com/bitcoin-sv/spv-wallet-go-client/queries"
	"github.com/bitcoin-sv/spv-wallet-web-backend/config"
	"github.com/bitcoin-sv/spv-wallet-web-backend/domain/users"
	"github.com/bitcoin-sv/spv-wallet/models"
	"github.com/bitcoin-sv/spv-wallet/models/common"
	"github.com/bitcoin-sv/spv-wallet/models/filter"
	"github.com/bitcoin-sv/spv-wallet/models/response"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"

	"github.com/bitcoin-sv/go-sdk/transaction"
	sdkTx "github.com/bitcoin-sv/go-sdk/transaction"

	overlayApi "github.com/4chain-AG/gateway-overlay/pkg/open_api"
	"github.com/4chain-AG/gateway-overlay/pkg/token_engine/bsv21"
)

type userClientAdapter struct {
	api *walletclient.UserAPI
	log *zerolog.Logger

	// I know it's not best place for the client, but I don't want to refacor whole project
	overlay     *overlayApi.Client
	knownTokens sync.Map
}

func (u *userClientAdapter) CreateAccessKey() (users.AccKey, error) {
	accessKey, err := u.api.GenerateAccessKey(context.Background(), &commands.GenerateAccessKey{})
	if err != nil {
		u.log.Error().Msgf("Error while creating new accessKey: %v", err.Error())
		return nil, errors.Wrap(err, "error while creating new accessKey ")
	}

	return &AccessKey{ID: accessKey.ID, Key: accessKey.Key}, nil
}

func (u *userClientAdapter) GetAccessKey(accessKeyID string) (users.AccKey, error) {
	accessKey, err := u.api.AccessKey(context.Background(), accessKeyID)
	if err != nil {
		u.log.Error().Str("accessKeyID", accessKeyID).Msgf("Error while getting accessKey: %v", err.Error())
		return nil, errors.Wrap(err, "error while getting accessKey")
	}

	return &AccessKey{ID: accessKey.ID, Key: accessKey.Key}, nil
}

func (u *userClientAdapter) RevokeAccessKey(accessKeyID string) (users.AccKey, error) {
	accessKey, err := u.api.AccessKey(context.Background(), accessKeyID)
	if err != nil {
		u.log.Error().Str("accessKeyID", accessKeyID).Msgf("Error while fetching accessKey: %v", err.Error())
		return nil, errors.Wrap(err, "error while fetching accessKey")
	}

	err = u.api.RevokeAccessKey(context.Background(), accessKeyID)
	if err != nil {
		u.log.Error().Str("accessKeyID", accessKeyID).Msgf("Error while revoking accessKey: %v", err.Error())
		return nil, errors.Wrap(err, "error while revoking accessKey")
	}

	return &AccessKey{ID: accessKey.ID, Key: accessKey.Key}, nil
}

// XPub Key methods
func (u *userClientAdapter) GetXPub() (users.PubKey, error) {
	xpub, err := u.api.XPub(context.Background())
	if err != nil {
		u.log.Error().Msgf("Error while getting new xPub: %v", err.Error())
		return nil, errors.Wrap(err, "error while getting new xPub")
	}

	return &XPub{ID: xpub.ID, CurrentBalance: xpub.CurrentBalance}, nil
}

func (c *userClientAdapter) GetUTXOs(ctx context.Context) ([]*transaction.UTXO, error) {
	spvUtxos, err := c.api.UTXOs(ctx)
	if err != nil {
		return nil, err
	}

	utxos, err := spvUtxosToUtxos(spvUtxos.Content)
	if err != nil {
		return nil, err
	}

	return utxos, nil
}

func (u *userClientAdapter) SendToRecipients(recipients []*commands.Recipients, senderPaymail string) (users.Transaction, error) {
	// Send transaction.
	transaction, err := u.api.SendToRecipients(context.Background(), &commands.SendToRecipients{
		Recipients: recipients,
		Metadata: map[string]any{
			"receiver": recipients[0].To,
			"sender":   senderPaymail,
		},
	})
	if err != nil {
		u.log.Error().Msgf("Error while creating new tx: %v", err.Error())
		return nil, errors.Wrap(err, "error while creating new tx")
	}

	return &Transaction{
		ID:         transaction.ID,
		Direction:  fmt.Sprint(transaction.TransactionDirection),
		TotalValue: transaction.TotalValue,
		Status:     transaction.Status,
		CreatedAt:  transaction.Model.CreatedAt,
	}, nil
}

func (u *userClientAdapter) GetTransactions(queryParam *filter.QueryParams, userPaymail string) ([]users.Transaction, error) {
	if queryParam.OrderByField == "" {
		queryParam.OrderByField = "created_at"
	}

	if queryParam.SortDirection == "" {
		queryParam.SortDirection = "desc"
	}

	page, err := u.api.Transactions(context.Background(), queries.QueryWithPageFilter[filter.TransactionFilter](filter.Page{
		Number: queryParam.Page,
		Size:   queryParam.PageSize,
		Sort:   queryParam.SortDirection,
		SortBy: queryParam.OrderByField,
	}))
	if err != nil {
		u.log.Error().Str("userPaymail", userPaymail).Msgf("Error while getting transactions: %v", err.Error())
		return nil, errors.Wrap(err, "error while getting transactions")
	}

	transactionsData := make([]users.Transaction, 0)
	for _, transaction := range page.Content {
		sender, receiver := GetPaymailsFromMetadata(transaction, userPaymail)
		status := "unconfirmed"
		if transaction.BlockHeight > 0 {
			status = "confirmed"
		}

		symbol, value, err := u.getTransacionValue(context.Background(), transaction)
		if err != nil {
			return nil, errors.Wrap(err, "error while getting token symbol")
		}

		transactionsData = append(transactionsData, &Transaction{
			ID:         transaction.ID,
			Direction:  fmt.Sprint(transaction.TransactionDirection),
			TotalValue: value,
			Symbol:     symbol,
			Fee:        transaction.Fee,
			Status:     status,
			CreatedAt:  transaction.Model.CreatedAt,
			Sender:     sender,
			Receiver:   receiver,
		})
	}

	return transactionsData, nil
}

func (u *userClientAdapter) GetTransaction(transactionID, userPaymail string) (users.FullTransaction, error) {
	transaction, err := u.api.Transaction(context.Background(), transactionID)
	if err != nil {
		u.log.Error().Str("transactionId", transactionID).Str("userPaymail", userPaymail).Msgf("Error while getting transaction: %v", err.Error())
		return nil, errors.Wrap(err, "error while getting transaction")
	}

	sender, receiver := GetPaymailsFromMetadata(transaction, userPaymail)
	symbol, value, err := u.getTransacionValue(context.Background(), transaction)
	if err != nil {
		return nil, errors.Wrap(err, "error while getting token symbol")
	}

	return &FullTransaction{
		ID:              transaction.ID,
		BlockHash:       transaction.BlockHash,
		BlockHeight:     transaction.BlockHeight,
		TotalValue:      value,
		Symbol:          symbol,
		Direction:       fmt.Sprint(transaction.TransactionDirection),
		Status:          transaction.Status,
		Fee:             transaction.Fee,
		NumberOfInputs:  transaction.NumberOfInputs,
		NumberOfOutputs: transaction.NumberOfOutputs,
		CreatedAt:       transaction.Model.CreatedAt,
		Sender:          sender,
		Receiver:        receiver,
	}, nil
}

func (u *userClientAdapter) GetTransactionsCount() (int64, error) {
	return 0, nil // Note: Functionality it's not a part of the SPV Wallet Go client.
}

func (u *userClientAdapter) CreateAndFinalizeTransaction(recipients []*commands.Recipients, metadata map[string]any) (users.DraftTransaction, error) {
	draftTx, err := u.api.SendToRecipients(context.Background(), &commands.SendToRecipients{
		Recipients: recipients,
		Metadata:   metadata,
	})
	if err != nil {
		u.log.Error().Msgf("Error while sending to recipients: %v", err.Error())
		return nil, errors.Wrap(err, "error while sending to recipients")
	}

	return &DraftTransaction{
		TxDraftID: draftTx.DraftID,
		TxHex:     draftTx.Hex,
	}, nil
}

func (u *userClientAdapter) DraftAndSignClassicTransaction(utxos []*transaction.UTXO, recipient string, amount uint64, metadata map[string]any) (users.DraftTransaction, error) {
	utxoPointers := make([]*response.UtxoPointer, len(utxos))
	for i, u := range utxos {
		utxoPointers[i] = &response.UtxoPointer{
			TransactionID: u.TxID.String(),
			OutputIndex:   u.Vout,
		}
	}

	draftTx, err := u.api.DraftTransaction(context.Background(), &commands.DraftTransaction{
		Config: response.TransactionConfig{
			FromUtxos: utxoPointers,
			Outputs: []*response.TransactionOutput{
				&response.TransactionOutput{
					To:       recipient,
					Satoshis: amount,
				},
			},
		},
		Metadata: metadata,
	})
	if err != nil {
		u.log.Error().Msgf("Error while preparing draftTx: %v", err.Error())
		return nil, errors.Wrap(err, "error preparing draftTx")
	}

	hex, err := u.api.FinalizeTransaction(draftTx)
	if err != nil {
		u.log.Error().Msgf("Error finalizing transaction: %v", err.Error())
		return nil, errors.Wrap(err, "error finalizing transaction")
	}

	return &DraftTransaction{
		TxDraftID: draftTx.ID,
		TxHex:     hex,
	}, nil
}

func (u *userClientAdapter) DraftAndSignTokenTransaction(tokenTransfer, tokenChange *users.TokenOutput, utxos []*transaction.UTXO, xpriv string, metadata map[string]any) (users.DraftTransaction, error) {
	if len(utxos) == 0 || tokenTransfer == nil {
		return nil, errors.New("missing token data or utxos")
	}

	utxoPointers := make([]*response.UtxoPointer, len(utxos))

	for i, u := range utxos {
		utxoPointers[i] = &response.UtxoPointer{
			TransactionID: u.TxID.String(),
			OutputIndex:   u.Vout,
		}
	}

	outputs := []*response.TransactionOutput{
		{
			To:       tokenTransfer.To,
			Satoshis: 1,
			Script:   tokenTransfer.Script,
		},
	}

	if tokenChange != nil {
		outputs = append(outputs, &response.TransactionOutput{
			To:       tokenChange.To,
			Satoshis: 1,
			Script:   tokenChange.Script,
		})
	}

	draft, err := u.api.DraftTransaction(context.Background(), &commands.DraftTransaction{
		Config: response.TransactionConfig{
			FromUtxos: utxoPointers,
			Outputs:   outputs,
		},
		Metadata: metadata,
	})
	if err != nil {
		return nil, fmt.Errorf("error preparing draft TX: %s", err.Error())
	}

	efHex, err := signTransactionEF(draft, xpriv)
	if err != nil {
		return nil, err
	}

	return &DraftTransaction{
		TxDraftID: draft.ID,
		TxHex:     efHex,
	}, nil
}

func (u *userClientAdapter) RecordTransaction(hex, draftTxID string, metadata map[string]any) (*models.Transaction, error) {
	tx, err := u.api.RecordTransaction(context.Background(), &commands.RecordTransaction{
		Metadata:    metadata,
		Hex:         hex,
		ReferenceID: draftTxID,
	})
	if err != nil {
		u.log.Error().Str("draftTxID", draftTxID).Msgf("Error while recording tx: %v", err.Error())
		return nil, errors.Wrap(err, "error while recording tx")
	}

	return &models.Transaction{
		Model:                common.Model(tx.Model),
		ID:                   tx.ID,
		Hex:                  tx.Hex,
		XpubInIDs:            tx.XpubInIDs,
		XpubOutIDs:           tx.XpubOutIDs,
		BlockHash:            tx.BlockHash,
		BlockHeight:          tx.BlockHeight,
		Fee:                  tx.Fee,
		NumberOfInputs:       tx.NumberOfInputs,
		NumberOfOutputs:      tx.NumberOfOutputs,
		DraftID:              tx.DraftID,
		TotalValue:           tx.TotalValue,
		OutputValue:          tx.OutputValue,
		Outputs:              tx.Outputs,
		Status:               tx.Status,
		TransactionDirection: tx.TransactionDirection,
	}, nil
}

// Contacts methods
func (u *userClientAdapter) UpsertContact(ctx context.Context, paymail, fullName, requesterPaymail string, metadata map[string]any) (*models.Contact, error) {
	contact, err := u.api.UpsertContact(ctx, commands.UpsertContact{
		ContactPaymail:   paymail,
		FullName:         fullName,
		Metadata:         metadata,
		RequesterPaymail: requesterPaymail,
	})
	if err != nil {
		return nil, errors.Wrap(err, "upsert contact error")
	}

	return &models.Contact{
		Model:    common.Model(contact.Model),
		ID:       contact.ID,
		FullName: contact.FullName,
		Paymail:  contact.Paymail,
		PubKey:   contact.PubKey,
		Status:   contact.Status,
	}, nil
}

func (u *userClientAdapter) AcceptContact(ctx context.Context, paymail string) error {
	return errors.Wrap(u.api.AcceptInvitation(ctx, paymail), "accept contact error")
}

func (u *userClientAdapter) RejectContact(ctx context.Context, paymail string) error {
	return errors.Wrap(u.api.RejectInvitation(ctx, paymail), "reject contact error")
}

func (u *userClientAdapter) ConfirmContact(ctx context.Context, contact *models.Contact, passcode, requesterPaymail string, period, digits uint) error {
	return errors.Wrap(u.api.ConfirmContact(ctx, contact, passcode, requesterPaymail, period, digits), "confirm contact error")
}

func (u *userClientAdapter) GetContacts(ctx context.Context, conditions *filter.ContactFilter, metadata map[string]any, queryParams *filter.QueryParams) (*models.SearchContactsResponse, error) {
	opts := []queries.QueryOption[filter.ContactFilter]{
		queries.QueryWithMetadataFilter[filter.ContactFilter](metadata),
	}

	if queryParams != nil {
		opts = append(opts,
			queries.QueryWithPageFilter[filter.ContactFilter](filter.Page{
				Number: queryParams.Page,
				Size:   queryParams.PageSize,
				Sort:   queryParams.SortDirection,
				SortBy: queryParams.OrderByField,
			}))
	}

	if conditions != nil {
		opts = append(opts,
			queries.QueryWithFilter(filter.ContactFilter{
				ModelFilter: conditions.ModelFilter,
				ID:          conditions.ID,
				FullName:    conditions.FullName,
				Paymail:     conditions.Paymail,
				PubKey:      conditions.PubKey,
				Status:      conditions.Status,
			}))
	}

	res, err := u.api.Contacts(ctx, opts...)
	if err != nil {
		u.log.Error().Msgf("Error while fetching contacts: %v", err.Error())
		return nil, errors.Wrap(err, "error while fetching contacts")
	}

	content := make([]*models.Contact, len(res.Content))
	for i, c := range res.Content {
		content[i] = &models.Contact{
			Model:    common.Model(c.Model),
			FullName: c.FullName,
			ID:       c.ID,
			Paymail:  c.Paymail,
			PubKey:   c.PubKey,
			Status:   c.Status,
		}
	}

	page := models.Page{
		TotalElements: int64(res.Page.TotalElements),
		TotalPages:    res.Page.TotalPages,
		Size:          res.Page.Size,
		Number:        res.Page.Number,
	}

	if queryParams != nil {
		page.OrderByField = &queryParams.OrderByField
		page.SortDirection = &queryParams.SortDirection
	}

	return &models.SearchContactsResponse{
		Content: content,
		Page:    page,
	}, nil
}

func (u *userClientAdapter) GenerateTotpForContact(contact *models.Contact, period, digits uint) (string, error) {
	totp, err := u.api.GenerateTotpForContact(contact, period, digits)
	return totp, errors.Wrap(err, "error while generating TOTP for contact")
}

func newUserClientAdapterWithXPriv(log *zerolog.Logger, xPriv string, overlay *overlayApi.Client) (*userClientAdapter, error) {
	serverURL := viper.GetString(config.EnvServerURL)
	api, err := walletclient.NewUserAPIWithXPriv(walletclientCfg.New(walletclientCfg.WithAddr(serverURL)), xPriv)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize user API")
	}

	return &userClientAdapter{
		api:     api,
		log:     log,
		overlay: overlay,
	}, nil
}

func newUserClientAdapterWithAccessKey(log *zerolog.Logger, accessKey string, overlay *overlayApi.Client) (*userClientAdapter, error) {
	serverURL := viper.GetString(config.EnvServerURL)
	api, err := walletclient.NewUserAPIWithAccessKey(walletclientCfg.New(walletclientCfg.WithAddr(serverURL)), accessKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize user API")
	}

	return &userClientAdapter{
		api:     api,
		log:     log,
		overlay: overlay,
	}, nil
}

func (u *userClientAdapter) getTransacionValue(ctx context.Context, transaction *response.Transaction) (symbol string, amount uint64, err error) {
	symbol = "" // satoshi
	amount = getAbsoluteValue(transaction.OutputValue)

	if isEF(transaction.Hex) {
		tx, _ := sdkTx.NewTransactionFromHex(transaction.Hex) // ignore corrupted transactions
		if ttxo := getStableCoinValue(transaction.ID, tx); ttxo != nil {
			symbol, err = u.getKnownTokenSymbol(context.Background(), ttxo)
			if err != nil {
				return "", 0, err
			}

			amount = ttxo.Amount
		}
	}

	u.log.Debug().Ctx(ctx).
		Str("sym", symbol).
		Msg("getTransacionValue - complete")
	return symbol, amount, nil
}

func (u *userClientAdapter) getKnownTokenSymbol(ctx context.Context, ttxo *bsv21.TokenOperation) (string, error) {
	symbol, ok := u.knownTokens.Load(ttxo.ID)
	if ok {
		return symbol.(string), nil //nolint: errcheck
	}

	token, err := u.getBsv21Token(ctx, ttxo.ID)
	if err != nil {
		return "", err
	}

	if token == nil || token.Symbol == nil {
		u.log.Warn().Ctx(ctx).
			Str("tokenID", ttxo.ID).
			Msg("Unknown token with no symbol")
		return ttxo.ID, nil // use tokenID as currency symbol for unknown tokens
	}

	u.knownTokens.Store(token.Id, *token.Symbol)
	return *token.Symbol, nil
}

func (u *userClientAdapter) getBsv21Token(ctx context.Context, tokenID string) (*overlayApi.GetTokenResponse, error) {
	resp, err := u.overlay.GetApiV1Bsv21TokenId(ctx, tokenID)
	if err != nil {
		u.log.Error().Ctx(ctx).Err(err).Msg("Failed connect with overlay service")
		return nil, err
	}

	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		var payload []byte
		payload, err = io.ReadAll(resp.Body)
		if err != nil {
			u.log.Error().Ctx(ctx).Err(err).Msg("Failed read response")
			return nil, err
		}

		res := new(overlayApi.GetTokenResponse)
		err = json.Unmarshal(payload, res)
		if err != nil {
			u.log.Error().Ctx(ctx).Err(err).Msg("Failed read response")
			return nil, err
		}

		return res, nil

	case 404:
		u.log.Warn().Ctx(ctx).Msg("Token not found")
		return nil, nil
	default:
		errorBody, _ := io.ReadAll(resp.Body)
		err = errors.New(string(errorBody))

		u.log.Error().Ctx(ctx).Err(err).Msg("Failed get token from overlay service")
		return nil, err
	}
}
