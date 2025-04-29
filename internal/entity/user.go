package entity

import "time"

type User struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	Role         string    `json:"is_admin"`
	PasswordHash []byte    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
}
