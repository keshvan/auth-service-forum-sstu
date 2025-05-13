package controller

import (
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/keshvan/auth-service-sstu-forum/internal/usecase"
	"github.com/keshvan/go-common-forum/jwt"
	"github.com/rs/zerolog"
)

func NewRouter(engine *gin.Engine, usecase usecase.AuthUsecase, jwt *jwt.JWT, log *zerolog.Logger) {
	h := &AuthHandler{usecase, log}

	engine.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173"},
		AllowMethods:     []string{"POST"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "Authorization"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	engine.POST("/register", h.Register)
	engine.POST("/login", h.Login)
	engine.POST("/refresh", h.Refresh)
	engine.POST("/logout", h.Logout)
	engine.GET("/check-session", h.CheckSession)
}
