package app

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/keshvan/auth-service-sstu-forum/config"
	"github.com/keshvan/auth-service-sstu-forum/internal/controller"
	"github.com/keshvan/auth-service-sstu-forum/internal/repo"
	"github.com/keshvan/auth-service-sstu-forum/internal/usecase"
	"github.com/keshvan/go-common-forum/httpserver"
	"github.com/keshvan/go-common-forum/jwt"
	"github.com/keshvan/go-common-forum/logger"
	"github.com/keshvan/go-common-forum/postgres"
)

func Run(cfg *config.Config) {
	//Logger
	logger := logger.New("auth-service", cfg.LogLevel)

	//Repository
	pg, err := postgres.New(cfg.PG_URL)
	if err != nil {
		log.Fatalf("app - Run - postgres.New")
	}
	defer pg.Close()

	if err := pg.RunMigrations(context.Background(), "migrations"); err != nil {
		log.Fatalf("app - Run - pg.RunMigrations: %v", err)
	}

	userRepo := repo.NewUserRepository(pg, logger)
	tokenRepo := repo.NewRefreshTokenRepository(pg, logger)

	//JWT
	fmt.Println(cfg.AccessTTL, cfg.RefreshTTL)
	jwt := jwt.New(cfg.Secret, cfg.AccessTTL, cfg.RefreshTTL)

	//Usecase
	authUsecase := usecase.NewAuthUsecase(userRepo, tokenRepo, jwt, logger)

	//HTTP-Server
	httpServer := httpserver.New(cfg.Server)
	controller.NewRouter(httpServer.Engine, authUsecase, jwt, logger)

	httpServer.Run()
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	<-interrupt
}
