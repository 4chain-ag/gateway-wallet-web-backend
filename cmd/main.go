package main

import (
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	overlayApi "github.com/4chain-AG/gateway-overlay/pkg/open_api"
	"github.com/bitcoin-sv/spv-wallet-web-backend/config"
	"github.com/bitcoin-sv/spv-wallet-web-backend/config/databases"
	db_users "github.com/bitcoin-sv/spv-wallet-web-backend/data/users"
	"github.com/bitcoin-sv/spv-wallet-web-backend/domain"
	"github.com/bitcoin-sv/spv-wallet-web-backend/logging"
	"github.com/bitcoin-sv/spv-wallet-web-backend/transports/http/endpoints"
	httpserver "github.com/bitcoin-sv/spv-wallet-web-backend/transports/http/server"
	"github.com/bitcoin-sv/spv-wallet-web-backend/transports/websocket"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

// @title           Gateway Wallet WEB Backend
// @version			1.0
// @description     This is an API for the gateway-wallet-web-frontend.
func main() {
	defaultLogger := logging.GetDefaultLogger()

	// Load config.
	config.NewViperConfig().
		WithDb()

	log, err := logging.CreateLogger()
	if err != nil {
		defaultLogger.Error().Msg("cannot create logger")
		os.Exit(1)
	}

	db := databases.SetUpDatabase(log)
	defer db.Close() //nolint: all

	repo := db_users.NewUsersRepository(db)

	overlayClient, _ := overlayApi.NewClient(viper.GetString(config.EnvTokenOverlayURL), overlayApi.WithHTTPClient(http.DefaultClient))

	s, err := domain.NewServices(repo, log, overlayClient)
	if err != nil {
		log.Error().Msgf("cannot create services because of an error: %v", err)
		os.Exit(1)
	}

	ws, err := websocket.NewServer(log, s, db)
	if err != nil {
		log.Error().Msgf("failed to init a new websocket server: %v", err)
		os.Exit(1)
	}
	err = ws.Start()
	if err != nil {
		log.Error().Msgf("failed to start websocket server: %v", err)
		os.Exit(1)
	}

	server := httpserver.NewHTTPServer(viper.GetInt(config.EnvHTTPServerPort), log)
	server.ApplyConfiguration(endpoints.SetupWalletRoutes(s, db, log, ws))
	server.ApplyConfiguration(ws.SetupEntrypoint)

	go startServer(server)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	<-quit

	if err = server.Shutdown(); err != nil {
		log.Error().Msgf("failed to stop http server: %v", err)
	}
	if err = ws.Shutdown(); err != nil {
		log.Error().Msgf("failed to stop websocket server: %v", err)
	}
}

func startServer(server *httpserver.HTTPServer) {
	if err := server.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error().Msgf("cannot start server because of an error: %v", err)
		os.Exit(1)
	}
}
