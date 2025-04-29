package entity

type (
	AccessClaims struct {
		UserID int64  `mapstructure:"user_id"`
		Role   string `mapstructure:"role"`
		Exp    int64  `mapstructure:"exp"`
		Iat    int64  `mapstructure:"iat"`
	}

	RefreshClaims struct {
		UserID int64 `mapstructure:"user_id"`
		Exp    int64 `mapstructure:"exp"`
		Iat    int64 `mapstructure:"iat"`
	}
)
