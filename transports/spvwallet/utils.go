package spvwallet

import (
	"fmt"
	"strings"

	"github.com/4chain-AG/gateway-overlay/pkg/token_engine/bsv21"
	"github.com/bitcoin-sv/go-sdk/chainhash"
	bip32 "github.com/bitcoin-sv/go-sdk/compat/bip32"
	"github.com/bitcoin-sv/go-sdk/script"
	"github.com/bitcoin-sv/go-sdk/transaction"
	sdkTx "github.com/bitcoin-sv/go-sdk/transaction"
	sighash "github.com/bitcoin-sv/go-sdk/transaction/sighash"
	"github.com/bitcoin-sv/go-sdk/transaction/template/p2pkh"
	"github.com/bitcoin-sv/spv-wallet/models/response"
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
	// Assumption: The first output token is the transferred value, others are treated as the remainder.
	// Someday, somehow, maybe this can be handled better, though I doubt it.

	for vout, out := range tx.Outputs {
		ins, _ := bsv21.FindInscription(out.LockingScript)
		if ins != nil {
			ttxo, err := bsv21.NewFromInscription(txID, uint32(vout), ins) //nolint: gosec
			if err != nil {
				// ignore and take next utxo
				continue
			}

			return ttxo
		}
	}

	return nil
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
