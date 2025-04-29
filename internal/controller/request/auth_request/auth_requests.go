package authrequest

type RegisterRequest struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
