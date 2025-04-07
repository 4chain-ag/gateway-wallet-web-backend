package users

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/mail"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bitcoin-sv/spv-wallet-web-backend/domain/rates"
	"github.com/bitcoin-sv/spv-wallet-web-backend/encryption"
	"github.com/bitcoin-sv/spv-wallet-web-backend/spverrors"
	"github.com/libsv/go-bk/bip32"
	"github.com/libsv/go-bk/bip39"
	"github.com/libsv/go-bk/chaincfg"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"

	overlayApi "github.com/4chain-AG/gateway-overlay/pkg/open_api"
	tokenengine "github.com/4chain-AG/gateway-overlay/pkg/token_engine"
)

// UserService represents User service and provide access to repository.
type UserService struct {
	repo                Repository
	ratesService        *rates.Service
	adminWalletClient   AdminWalletClient
	walletClientFactory WalletClientFactory
	log                 *zerolog.Logger

	// I know it's not best place for the client, but I don't want to refacor whole project
	overlay     *overlayApi.Client
	knownTokens sync.Map
}

// NewUserService creates UserService instance.
func NewUserService(repo Repository, adminWalletClient AdminWalletClient, walletClientFactory WalletClientFactory, rService *rates.Service, l *zerolog.Logger, overlay *overlayApi.Client) *UserService {
	userServiceLogger := l.With().Str("service", "user-service").Logger()
	s := &UserService{
		repo:                repo,
		adminWalletClient:   adminWalletClient,
		walletClientFactory: walletClientFactory,
		ratesService:        rService,
		log:                 &userServiceLogger,
		overlay:             overlay,
	}

	return s
}

// InsertUser inserts user to database.
func (s *UserService) InsertUser(user *User) error {
	if err := s.repo.InsertUser(context.Background(), user); err != nil {
		s.log.Error().Msgf("Error while inserting user: %v", err.Error())
		return spverrors.ErrInsertUser
	}
	return nil
}

// CreateNewUser creates new user.
func (s *UserService) CreateNewUser(email, password string) (*CreatedUser, error) {
	if emptyString(password) {
		return nil, spverrors.ErrEmptyPassword
	}

	if err := s.validateUser(email); err != nil {
		return nil, err
	}

	mnemonic, seed, err := generateMnemonic()
	if err != nil {
		s.log.Error().Msgf("Error while generating mnemonic: %v", err.Error())
		return nil, spverrors.ErrGenerateMnemonic
	}

	xpriv, err := generateXpriv(seed)
	if err != nil {
		s.log.Error().Msgf("Error while generating xPriv: %v", err.Error())
		return nil, spverrors.ErrGenerateXPriv
	}

	encryptedXpriv, err := encryptXpriv(password, xpriv.String())
	if err != nil {
		s.log.Error().Msgf("Error while encrypting xPriv: %v", err.Error())
		return nil, spverrors.ErrEncryptXPriv
	}

	xpub, err := s.adminWalletClient.RegisterXpub(xpriv)
	if err != nil {
		s.log.Error().Msgf("Error while registering xPub: %v", err.Error())
		return nil, spverrors.ErrRegisterXPub
	}

	username, _ := splitEmail(email)

	paymail, err := s.adminWalletClient.RegisterPaymail(username, xpub)
	if err != nil {
		s.log.Error().
			Str("alias", username).
			Msgf("Error while registering paymail: %v", err.Error())
		return nil, spverrors.ErrRegisterPaymail
	}

	user := &User{
		Email:     email,
		Xpriv:     encryptedXpriv,
		Paymail:   paymail,
		CreatedAt: time.Now(),
	}

	if err = s.InsertUser(user); err != nil {
		return nil, spverrors.ErrInsertUser
	}

	newUSerData := &CreatedUser{
		User:     user,
		Mnemonic: mnemonic,
	}

	return newUSerData, err
}

// SignInUser signs in user.
func (s *UserService) SignInUser(email, password string) (*AuthenticatedUser, error) {
	user, err := s.repo.GetUserByEmail(context.Background(), email)
	if err != nil {
		s.log.Error().
			Str("userEmail", email).
			Msgf("User wasn't found by email: %v", err.Error())
		return nil, spverrors.ErrGetUser
	}

	if user == nil {
		return nil, spverrors.ErrInvalidCredentials
	}

	decryptedXpriv, err := decryptXpriv(password, user.Xpriv)
	if err != nil {
		s.log.Error().
			Str("userEmail", email).
			Msgf("Error while decrypting xPriv: %v", err.Error())
		return nil, spverrors.ErrInvalidCredentials
	}

	userWalletClient, err := s.walletClientFactory.CreateWithXpriv(decryptedXpriv)
	if err != nil {
		return nil, spverrors.ErrInvalidCredentials.Wrap(err)
	}

	accessKey, err := userWalletClient.CreateAccessKey()
	if err != nil {
		s.log.Error().
			Str("userEmail", email).
			Msgf("Error while creating access key: %v", err.Error())
		return nil, spverrors.ErrCreateAccessKey
	}

	xpub, err := userWalletClient.GetXPub()
	if err != nil {
		s.log.Error().
			Str("userEmail", email).
			Msgf("Error while getting xPub: %v", err.Error())
		return nil, spverrors.ErrGetXPub
	}

	exchangeRate, err := s.ratesService.GetExchangeRate()
	if err != nil {
		s.log.Error().
			Msgf("Exchange rate not found: %v", err.Error())
		return nil, spverrors.ErrRateNotFound
	}

	balance := calculateBalance(xpub.GetCurrentBalance(), exchangeRate)

	signInUser := &AuthenticatedUser{
		User: user,
		AccessKey: AccessKey{
			ID:  accessKey.GetAccessKeyID(),
			Key: accessKey.GetAccessKey(),
		},
		Balance: *balance,
		Xpriv:   decryptedXpriv,
	}

	return signInUser, nil
}

// GetUserByID returns user by id.
func (s *UserService) GetUserByID(userID int) (*User, error) {
	user, err := s.repo.GetUserByID(context.Background(), userID)
	if err != nil {
		s.log.Error().
			Str("userID", strconv.Itoa(userID)).
			Msgf("Error while getting user by id: %v", err.Error())
		return nil, spverrors.ErrGetUser
	}

	return user, nil
}

// GetUserBalance returns user balance using access key.
func (s *UserService) GetUserBalance(accessKey string) (*Balance, error) {
	userWalletClient, err := s.walletClientFactory.CreateWithAccessKey(accessKey)
	if err != nil {
		return nil, spverrors.ErrGetBalance.Wrap(err)
	}

	// Get xpub.
	utxos, err := userWalletClient.GetUTXOs(context.Background())
	if err != nil {
		s.log.Error().Msgf("Error while getting utxos: %v", err.Error())
		return nil, spverrors.ErrGetXPub
	}

	exchangeRate, err := s.ratesService.GetExchangeRate()
	if err != nil {
		s.log.Error().Msgf("Exchange rate not found: %v", err.Error())
		return nil, spverrors.ErrRateNotFound
	}

	balance := tokenengine.CalculateBalance(utxos)
	bsvBalance := calculateBalance(balance[""], exchangeRate)
	for tokenID, amount := range balance {
		if tokenID == "" {
			continue
		}

		symbol, err := s.getKnownTokenSymbol(context.Background(), tokenID)
		if err != nil {
			s.log.Error().Msgf("Failed to get token symbol: %v", err.Error())
			return nil, spverrors.ErrRateNotFound
		}

		bsvBalance.Stablecoins = append(bsvBalance.Stablecoins, &StablecoinBalance{
			TokenID: tokenID,
			Symbol:  symbol,
			Amount:  amount,
		})
	}

	return bsvBalance, nil
}

// GetUserXpriv gets user by id and decrypt xpriv.
func (s *UserService) GetUserXpriv(userID int, password string) (string, error) {
	user, err := s.repo.GetUserByID(context.Background(), userID)
	if err != nil {
		s.log.Error().
			Str("userID", strconv.Itoa(userID)).
			Msgf("Error while getting user by id: %v", err.Error())

		return "", spverrors.ErrGetUser
	}

	// Decrypt xpriv.
	decryptedXpriv, err := decryptXpriv(password, user.Xpriv)
	if err != nil {
		s.log.Error().
			Str("userID", strconv.Itoa(userID)).
			Msgf("Error while decrypting xPriv: %v", err.Error())
		return "", spverrors.ErrInvalidCredentials
	}

	return decryptedXpriv, nil
}

func (s *UserService) validateUser(email string) error {
	// Validate email
	if _, err := mail.ParseAddress(email); err != nil {
		s.log.Debug().
			Str("userEmail", email).
			Msgf("Error while validating email: %v", err.Error())
		return spverrors.ErrIncorrectEmail
	}

	// Check if user with email already exists.
	user, err := s.repo.GetUserByEmail(context.Background(), email)
	if err != nil {
		return errors.Wrap(err, "Cannot get user by email")
	}

	if user != nil {
		return spverrors.ErrUserAlreadyExists
	}

	return nil
}

// generateMnemonic generates mnemonic and seed.
func generateMnemonic() (string, []byte, error) {
	entropy, err := bip39.GenerateEntropy(160)
	if err != nil {
		return "", nil, err //nolint:wrapcheck // error wrapped higher in call stack
	}

	return bip39.Mnemonic(entropy, "") //nolint:wrapcheck // error wrapped higher in call stack
}

// generateXpriv generates xpriv from seed.
func generateXpriv(seed []byte) (*bip32.ExtendedKey, error) {
	xpriv, err := bip32.NewMaster(seed, &chaincfg.MainNet)
	if err != nil {
		return nil, err //nolint:wrapcheck // error wrapped higher in call stack
	}
	return xpriv, nil
}

// encryptXpriv encrypts xpriv with password.
func encryptXpriv(password, xpriv string) (string, error) {
	// Create hash from password
	hashedPassword, err := encryption.Hash(password)
	if err != nil {
		return "", err //nolint:wrapcheck // error wrapped higher in call stack
	}

	// Encrypt xpriv with hashed password
	encryptedXpriv, err := encryption.Encrypt(hashedPassword, xpriv)
	if err != nil {
		return "", err //nolint:wrapcheck // error wrapped higher in call stack
	}

	return encryptedXpriv, nil
}

// decryptXpriv decrypts xpriv with password.
func decryptXpriv(password, encryptedXpriv string) (string, error) {
	// Create hash from password
	hashedPassword, err := encryption.Hash(password)
	if err != nil {
		return "", fmt.Errorf("internal error: %w", err)
	}

	// Decrypt xpriv with hashed password
	xpriv := encryption.Decrypt(hashedPassword, encryptedXpriv)
	if xpriv == "" {
		return "", spverrors.ErrInvalidCredentials
	}

	return xpriv, nil
}

// splitEmail splits email to username and domain.
func splitEmail(email string) (string, string) {
	components := strings.Split(email, "@")
	username, domain := components[0], components[1]

	return username, domain
}

func emptyString(input string) bool {
	trimed := strings.TrimSpace(input)
	return trimed == ""
}

func calculateBalance(satoshis uint64, exchangeRate *float64) *Balance {
	balanceBSV := float64(satoshis) / 100000000
	balanceUSD := balanceBSV * *exchangeRate

	balance := &Balance{
		Bsv:      balanceBSV,
		Usd:      balanceUSD,
		Satoshis: satoshis,
	}

	return balance
}

func (u *UserService) getKnownTokenSymbol(ctx context.Context, tokenID string) (string, error) {
	symbol, ok := u.knownTokens.Load(tokenID)
	if ok {
		return symbol.(string), nil //nolint: errcheck
	}

	token, err := u.getBsv21Token(ctx, tokenID)
	if err != nil {
		return "", err
	}

	if token == nil || token.Symbol == nil {
		u.log.Warn().Ctx(ctx).
			Str("tokenID", tokenID).
			Msg("Unknown token with no symbol")
		return tokenID, nil // use tokenID as currency symbol for unknown tokens
	}

	u.knownTokens.Store(token.Id, *token.Symbol)
	return *token.Symbol, nil
}

func (u *UserService) getBsv21Token(ctx context.Context, tokenID string) (*overlayApi.GetTokenResponse, error) {
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
