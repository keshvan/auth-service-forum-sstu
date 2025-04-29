package app

import (
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
	"github.com/keshvan/go-common-forum/postgres"
)

func Run(cfg *config.Config) {
	//Repository
	pg, err := postgres.New(cfg.PG_URL)
	if err != nil {
		log.Fatalf("app - Run - postgres.New")
	}
	defer pg.Close()

	userRepo := repo.NewUserRepository(pg)
	tokenRepo := repo.NewRefreshTokenRepository(pg)

	//JWT
	jwt := jwt.New(cfg.Secret, cfg.AccessTTL, cfg.RefreshTTL)

	//Usecase
	authUsecase := usecase.NewAuthUsecase(userRepo, tokenRepo, jwt)

	//HTTP-Server
	httpServer := httpserver.New(cfg.Server)
	controller.NewRouter(httpServer.Engine, authUsecase, jwt)

	httpServer.Run()
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	<-interrupt
}
