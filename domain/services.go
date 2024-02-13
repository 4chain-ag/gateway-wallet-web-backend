package domain

import (
	db_users "web-backend/data/users"
	"web-backend/domain/transactions"
	"web-backend/domain/users"
	"web-backend/transports/client"

	"github.com/rs/zerolog"
)

// Services is a struct that contains all services.
type Services struct {
	UsersService        *users.UserService
	TransactionsService *transactions.TransactionService
	BuxClientFactory    users.BuxClientFactory
}

// NewServices creates services instance.
func NewServices(usersRepo *db_users.UsersRepository, log *zerolog.Logger) (*Services, error) {
	bf := client.NewClientFactory(log)
	adminBuxClient, err := bf.CreateAdminClient()
	if err != nil {
		return nil, err
	}

	// Create User services.
	uService := users.NewUserService(usersRepo, adminBuxClient, bf, log)

	return &Services{
		UsersService:        uService,
		TransactionsService: transactions.NewTransactionService(adminBuxClient, bf, log),
		BuxClientFactory:    bf,
	}, nil
}
