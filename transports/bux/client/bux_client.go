package buxclient

import (
	"context"
	"fmt"

	"bux-wallet/domain/users"
	"bux-wallet/logging"

	"github.com/BuxOrg/bux"
	"github.com/BuxOrg/go-buxclient"
	"github.com/BuxOrg/go-buxclient/transports"
	"github.com/mrz1836/go-datastore"
)

// BuxClient is a wrapper for Bux Client.
type BuxClient struct {
	client *buxclient.BuxClient
	log    logging.Logger
}

// CreateAccessKey creates new access key for user.
func (c *BuxClient) CreateAccessKey() (users.AccKey, error) {
	accessKey, err := c.client.CreateAccessKey(context.Background(), &bux.Metadata{})
	if err != nil {
		return nil, err
	}

	accessKeyData := AccessKey{
		Id:  accessKey.ID,
		Key: accessKey.Key,
	}

	return &accessKeyData, err
}

// GetAccessKey checks if access key is valid.
func (c *BuxClient) GetAccessKey(accessKeyId string) (users.AccKey, error) {
	accessKey, err := c.client.GetAccessKey(context.Background(), accessKeyId)
	if err != nil {
		return nil, err
	}

	accessKeyData := AccessKey{
		Id:  accessKey.ID,
		Key: accessKey.Key,
	}

	return &accessKeyData, nil
}

// RevokeAccessKey revokes access key.
func (c *BuxClient) RevokeAccessKey(accessKeyId string) (users.AccKey, error) {
	accessKey, err := c.client.RevokeAccessKey(context.Background(), accessKeyId)
	if err != nil {
		return nil, err
	}

	accessKeyData := AccessKey{
		Id:  accessKey.ID,
		Key: accessKey.Key,
	}

	return &accessKeyData, nil
}

// GetXPub returns xpub.
func (c *BuxClient) GetXPub() (users.PubKey, error) {
	xpub, err := c.client.GetXPub(context.Background())
	if err != nil {
		return nil, err
	}

	xPub := XPub{
		Id:             xpub.ID,
		XPub:           xpub.Model.RawXpub(),
		CurrentBalance: xpub.CurrentBalance,
	}

	return &xPub, nil
}

// SendToRecipents sends satoshis to recipients.
func (c *BuxClient) SendToRecipents(recipients []*transports.Recipients) (users.Transaction, error) {
	transaction, err := c.client.SendToRecipients(context.Background(), recipients, &bux.Metadata{})
	if err != nil {
		return nil, err
	}

	t := &Transaction{
		Id:         transaction.ID,
		Direction:  fmt.Sprint(transaction.Direction),
		TotalValue: transaction.TotalValue,
		Status:     transaction.Status.String(),
		CreatedAt:  transaction.CreatedAt,
	}
	return t, nil
}

// GetTransactions returns all transactions.
func (c *BuxClient) GetTransactions(queryParam datastore.QueryParams) ([]users.Transaction, error) {
	conditions := make(map[string]interface{})

	if queryParam.OrderByField == "" {
		queryParam.OrderByField = "created_at"
	}

	if queryParam.SortDirection == "" {
		queryParam.SortDirection = "desc"
	}

	transactions, err := c.client.GetTransactions(context.Background(), conditions, &bux.Metadata{}, &queryParam)
	if err != nil {
		return nil, err
	}

	var transactionsData = make([]users.Transaction, 0)
	for _, transaction := range transactions {
		status := "unconfirmed"
		if transaction.BlockHeight > 0 {
			status = "confirmed"
		}
		transactionData := Transaction{
			Id:         transaction.ID,
			Direction:  fmt.Sprint(transaction.Direction),
			TotalValue: transaction.TotalValue,
			Status:     status,
			CreatedAt:  transaction.CreatedAt,
		}
		transactionsData = append(transactionsData, &transactionData)
	}

	return transactionsData, nil
}

// GetTransaction returns transaction by id.
func (c *BuxClient) GetTransaction(transactionId string) (users.FullTransaction, error) {
	transaction, err := c.client.GetTransaction(context.Background(), transactionId)
	if err != nil {
		return nil, err
	}

	transactionData := FullTransaction{
		Id:              transaction.ID,
		BlockHash:       transaction.BlockHash,
		BlockHeight:     transaction.BlockHeight,
		TotalValue:      transaction.TotalValue,
		Direction:       fmt.Sprint(transaction.Direction),
		Status:          transaction.Status.String(),
		Fee:             transaction.Fee,
		NumberOfInputs:  transaction.NumberOfInputs,
		NumberOfOutputs: transaction.NumberOfOutputs,
		CreatedAt:       transaction.CreatedAt,
	}

	return &transactionData, nil
}
