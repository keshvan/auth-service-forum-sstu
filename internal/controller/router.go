package controller

import (
	"github.com/gin-gonic/gin"
	"github.com/keshvan/auth-service-sstu-forum/internal/usecase"
)

func NewRouter(engine *gin.Engine, usecase usecase.AuthUsecase) {
	h := &AuthHandler{usecase}

	auth := engine.Group("/auth")
	{
		auth.POST("/register", h.Register)
		auth.POST("/login", h.Login)
		auth.POST("/refresh", h.Refresh)
	}
}
