package spvwallet

import (
	"fmt"
	"strings"

	"github.com/4chain-AG/gateway-overlay/pkg/token_engine/bsv21"
	"github.com/bitcoin-sv/spv-wallet/models/response"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	bip32 "github.com/bsv-blockchain/go-sdk/compat/bip32"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sdkTx "github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

func spvUtxosToUtxos(src []*response.Utxo) ([]*transaction.UTXO, error) {
	res := make([]*transaction.UTXO, 0, len(src))

	for _, u := range src {
		if u.SpendingTxID != "" {
			// don't include already spent UTXOs
			continue
		}

		txid, err := chainhash.NewHashFromHex(u.TransactionID)
		if err != nil {
			return nil, err
		}

		script, err := script.NewFromHex(u.ScriptPubKey)
		if err != nil {
			return nil, err
		}

		res = append(res, &transaction.UTXO{
			TxID:          txid,
			Vout:          u.OutputIndex,
			LockingScript: script,
			Satoshis:      u.Satoshis,
		})
	}

	return res, nil
}

func isEF(hex string) bool {
	const efMarker = "0000000000EF"
	return len(hex) > 20 && strings.EqualFold(hex[8:20], efMarker)
}

func getStableCoinValue(txID string, tx *sdkTx.Transaction, txOutputsIndexes, txFeeIndexes []int, txDirection string) *bsv21.TokenOperation {
	if len(txOutputsIndexes) == 0 {
		return nil
	}

	result := processIndexes(txID, tx, txOutputsIndexes)

	if txDirection == "outgoing" {
		feeToken := processIndexes(txID, tx, txFeeIndexes)
		if result == nil {
			result = feeToken
		} else if feeToken != nil {
			result.Amount += feeToken.Amount
		}
	}

	return result
}

// A helper function to reduce code duplication
func processIndexes(txID string, tx *sdkTx.Transaction, indexes []int) *bsv21.TokenOperation {
	var tokenOp *bsv21.TokenOperation
	for _, vout := range indexes {
		if vout >= len(tx.Outputs) || vout < 0 {
			continue // Skip invalid index
		}

		ins, _ := bsv21.FindInscription(tx.Outputs[vout].LockingScript)
		if ins == nil {
			continue
		}

		ttxo, err := bsv21.NewFromInscription(txID, uint32(vout), ins)
		if err != nil {
			continue // Ignore and take the next utxo
		}

		if tokenOp == nil {
			// This assumes all tokens have the same metadata, which is consistent with the original logic.
			tokenOp = &bsv21.TokenOperation{
				ID:        ttxo.ID,
				Amount:    ttxo.Amount,
				Symbol:    ttxo.Symbol,
				Decimals:  ttxo.Decimals,
				Icon:      ttxo.Icon,
				Meta:      ttxo.Meta,
				Operation: ttxo.Operation,
				SrcTxID:   ttxo.SrcTxID,
				SrcVout:   ttxo.SrcVout,
			}
		} else {
			tokenOp.Amount += ttxo.Amount
		}
	}
	return tokenOp
}

func signTransactionEF(draft *response.DraftTransaction, xPriv string) (efHex string, err error) {
	type utxoPointer struct {
		TxID        string
		OutputIndex uint32
	}
	draftInputsLookup := make(map[utxoPointer]*response.TransactionInput)

	for _, draftInput := range draft.Configuration.Inputs {
		key := utxoPointer{TxID: draftInput.TransactionID, OutputIndex: draftInput.OutputIndex}
		draftInputsLookup[key] = draftInput
	}

	tx, err := transaction.NewTransactionFromHex(draft.Hex)
	if err != nil {
		return "", fmt.Errorf("error parsing transaction hex: %w", err)
	}

	for _, input := range tx.Inputs {
		key := utxoPointer{TxID: input.SourceTXID.String(), OutputIndex: input.SourceTxOutIndex}
		draftInput := draftInputsLookup[key]

		xPriv, err := bip32.GenerateHDKeyFromString(xPriv)
		if err != nil {
			return "", fmt.Errorf("failed to parse xpriv: %w", err)
		}

		derivedKey, err := bip32.GetHDKeyByPath(xPriv, draftInput.Destination.Chain, draftInput.Destination.Num)
		if err != nil {
			return "", fmt.Errorf("failed to derive key for unlocking input: %w", err)
		}

		if draftInput.Destination.PaymailExternalDerivationNum != nil {
			derivedKey, err = derivedKey.Child(*draftInput.Destination.PaymailExternalDerivationNum)
			if err != nil {
				return "", fmt.Errorf("failed to derive key for unlocking paymail input, %w", err)
			}
		}

		priv, err := bip32.GetPrivateKeyFromHDKey(derivedKey)
		if err != nil {
			return "", fmt.Errorf("failed to get private key for unlocking input: %w", err)
		}

		sigHashFlags := sighash.AllForkID
		unlockScript, err := p2pkh.Unlock(priv, &sigHashFlags)
		if err != nil {
			return "", fmt.Errorf("error creating an unlocker: %w", err)
		}

		input.UnlockingScriptTemplate = unlockScript
	}

	err = tx.Sign()
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	return tx.EFHex()
}
