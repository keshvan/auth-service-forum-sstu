package entity

type (
	RegisterRequest struct {
		Username string `json:"username" example:"user"`
		Password string `json:"password" example:"pa55word"`
		IsAdmin  bool   `json:"is_admin" example:"true"`
	}
	LoginRequest struct {
		Username string `json:"username" example:"user"`
		Password string `json:"password" example:"pa55word"`
	}
	RefreshRequest struct {
		RefreshToken string `json:"username" example:"token"`
	}
)
