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

func getStableCoinValue(txID string, tx *sdkTx.Transaction) *bsv21.TokenOperation {
	// Assumption: First unique tokens in outputs are transaction tokens sent to the recipient
	// If any token after it's first been seen repeats itself it is a reminder send to the sender
	// Someday, somehow, maybe this can be handled better, though I doubt it.
	seenTokens := make(map[bsv21.TokenID]bool)
	var result *bsv21.TokenOperation

	for vout, out := range tx.Outputs {
		ins, _ := bsv21.FindInscription(out.LockingScript)
		if ins != nil {
			ttxo, err := bsv21.NewFromInscription(txID, uint32(vout), ins) //nolint: gosec
			if err != nil {
				// ignore and take next utxo
				continue
			}

			if vout == 0 {
				// assign only first ttxo as our result as the data should be the same for all of them and only amount should be different
				result = &bsv21.TokenOperation{
					ID:        ttxo.ID,
					Amount:    0,
					Symbol:    ttxo.Symbol,
					Decimals:  ttxo.Decimals,
					Icon:      ttxo.Icon,
					Meta:      ttxo.Meta,
					Operation: ttxo.Operation,
					SrcTxID:   ttxo.SrcTxID,
					SrcVout:   ttxo.SrcVout,
				}
			}

			if result != nil {
				// I assume if the token was already seen in outputs it means its a reminder
				_, alreadySeen := seenTokens[ttxo.ID]
				if !alreadySeen {
					seenTokens[ttxo.ID] = true
					result.Amount += ttxo.Amount
				}
			}
		}
	}

	return result
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
