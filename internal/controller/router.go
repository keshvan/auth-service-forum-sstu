package controller

import (
	"github.com/gin-gonic/gin"
	"github.com/keshvan/auth-service-sstu-forum/internal/usecase"
	"github.com/keshvan/go-common-forum/jwt"
)

func NewRouter(engine *gin.Engine, usecase usecase.AuthUsecase, jwt *jwt.JWT) {
	h := &AuthHandler{usecase}

	engine.POST("/register", h.Register)
	engine.POST("/login", h.Login)
	engine.POST("/refresh", h.Refresh)
	engine.POST("/logout", h.Logout)
}
