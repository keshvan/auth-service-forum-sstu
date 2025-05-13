package authresponse

import "github.com/keshvan/auth-service-sstu-forum/internal/entity"

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RegisterResponse struct {
	User   entity.User `json:"user"`
	Tokens Tokens      `json:"tokens"`
}

type LoginResponse struct {
	User   entity.User `json:"user"`
	Tokens Tokens      `json:"tokens"`
}

type RefreshResponse struct {
	User   entity.User `json:"user"`
	Tokens Tokens      `json:"tokens"`
}

type IsSessionActiveResponse struct {
	User     *entity.User `json:"user"`
	IsActive bool         `json:"is_active"`
}
