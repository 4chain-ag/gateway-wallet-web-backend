package spvwallet

import "time"

// AccessKey is a struct that contains access key data.
type AccessKey struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

// XPub is a struct that contains xpub data.
type XPub struct {
	ID             string `json:"id"`
	CurrentBalance uint64 `json:"current_balance"`
}

// Transaction is a struct that contains transaction data.
type Transaction struct {
	ID         string    `json:"id"`
	Direction  string    `json:"direction"`
	TotalValue uint64    `json:"totalValue"`
	Symbol     string    `json:"symbol"`
	Fee        uint64    `json:"fee"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"createdAt"`
	Sender     string    `json:"sender"`
	Receiver   string    `json:"receiver"`
}

// FullTransaction is a struct that contains extended transaction data.
type FullTransaction struct {
	ID              string    `json:"id"`
	BlockHash       string    `json:"blockHash"`
	BlockHeight     uint64    `json:"blockHeight"`
	TotalValue      uint64    `json:"totalValue"`
	Symbol          string    `json:"symbol"`
	Direction       string    `json:"direction"`
	Status          string    `json:"status"`
	Fee             uint64    `json:"fee"`
	NumberOfInputs  uint32    `json:"numberOfInputs"`
	NumberOfOutputs uint32    `json:"numberOfOutputs"`
	CreatedAt       time.Time `json:"createdAt"`
	Sender          string    `json:"sender"`
	Receiver        string    `json:"receiver"`
}

// DraftTransaction is a struct that contains draft transaction data.
type DraftTransaction struct {
	TxDraftID string `json:"txDraftId"`
	TxHex     string `json:"txHex"`
}

// GetAccessKey returns access key.
func (a *AccessKey) GetAccessKey() string {
	return a.Key
}

// GetAccessKeyID returns access key id.
func (a *AccessKey) GetAccessKeyID() string {
	return a.ID
}

// GetID returns xpub id.
func (x *XPub) GetID() string {
	return x.ID
}

// GetCurrentBalance returns current balance.
func (x *XPub) GetCurrentBalance() uint64 {
	return x.CurrentBalance
}

// GetTransactionID returns transaction id.
func (t *Transaction) GetTransactionID() string {
	return t.ID
}

// GetTransactionDirection returns transaction direction.
func (t *Transaction) GetTransactionDirection() string {
	return t.Direction
}

// GetTransactionTotalValue returns transaction total value.
func (t *Transaction) GetTransactionTotalValue() uint64 {
	return t.TotalValue
}

// GetTransactionSymbol returns transaction currency symbol.
func (t *Transaction) GetTransactionSymbol() string {
	return t.Symbol
}

// GetTransactionFee returns transaction fee.
func (t *Transaction) GetTransactionFee() uint64 {
	return t.Fee
}

// GetTransactionStatus returns transaction status.
func (t *Transaction) GetTransactionStatus() string {
	return t.Status
}

// GetTransactionCreatedDate returns transaction created at.
func (t *Transaction) GetTransactionCreatedDate() time.Time {
	return t.CreatedAt
}

// GetTransactionSender returns transaction sender.
func (t *Transaction) GetTransactionSender() string {
	return t.Sender
}

// GetTransactionReceiver returns transaction receiver.
func (t *Transaction) GetTransactionReceiver() string {
	return t.Receiver
}

// GetTransactionID returns transaction id.
func (t *FullTransaction) GetTransactionID() string {
	return t.ID
}

// GetTransactionBlockHash returns transaction block hash.
func (t *FullTransaction) GetTransactionBlockHash() string {
	return t.BlockHash
}

// GetTransactionBlockHeight returns transaction block height.
func (t *FullTransaction) GetTransactionBlockHeight() uint64 {
	return t.BlockHeight
}

// GetTransactionTotalValue returns transaction total value.
func (t *FullTransaction) GetTransactionTotalValue() uint64 {
	return t.TotalValue
}

// GetTransactionSymbol returns transaction currency symbol.
func (t *FullTransaction) GetTransactionSymbol() string {
	return t.Symbol
}

// GetTransactionDirection returns transaction direction.
func (t *FullTransaction) GetTransactionDirection() string {
	return t.Direction
}

// GetTransactionStatus returns transaction status.
func (t *FullTransaction) GetTransactionStatus() string {
	return t.Status
}

// GetTransactionFee returns transaction fee.
func (t *FullTransaction) GetTransactionFee() uint64 {
	return t.Fee
}

// GetTransactionNumberOfInputs returns transaction number of inputs.
func (t *FullTransaction) GetTransactionNumberOfInputs() uint32 {
	return t.NumberOfInputs
}

// GetTransactionNumberOfOutputs returns transaction number of outputs.
func (t *FullTransaction) GetTransactionNumberOfOutputs() uint32 {
	return t.NumberOfOutputs
}

// GetTransactionCreatedDate returns transaction created date.
func (t *FullTransaction) GetTransactionCreatedDate() time.Time {
	return t.CreatedAt
}

// GetTransactionSender returns transaction sender.
func (t *FullTransaction) GetTransactionSender() string {
	return t.Sender
}

// GetTransactionReceiver returns transaction receiver.
func (t *FullTransaction) GetTransactionReceiver() string {
	return t.Receiver
}

// GetDraftTransactionID returns draft transaction id.
func (t *DraftTransaction) GetDraftTransactionID() string {
	return t.TxDraftID
}

// GetDraftTransactionHex returns draft transaction hex.
func (t *DraftTransaction) GetDraftTransactionHex() string {
	return t.TxHex
}

type Balance struct {
	Satoshis    uint64               `json:"satoshis"`
	Stablecoins []*StablecoinBalance `json:"stablecoins"`
}

type StablecoinBalance struct {
	TokenID string `json:"tokenId"`
	Symbol  string `json:"symbol"`
	Amount  uint64 `json:"amount"`
}
