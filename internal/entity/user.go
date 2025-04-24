package entity

type User struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	IsAdmin      bool   `json:"is_admin"`
	PasswordHash []byte `json:"password_hash"`
}
