package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Env      string        `yaml:"env" env-default:"local"`
	PG_URL   string        `yaml:"pg_url"`
	TokenTTL time.Duration `yaml:"token_ttl" env-required:"true"`
	Log      string        `yaml:"log_level"`
}

/*type GRPCConfig struct {
	Port    int           `yaml:"port"`
	Timeout time.Duration `yaml:"timeout"`
}*/

func NewConfig() (*Config, error) {
	cfg := &Config{}
	file, err := os.ReadFile("./config.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	if err := yaml.Unmarshal(file, cfg); err != nil {
		return nil, fmt.Errorf("config error: %w", err)
	}

	return cfg, nil
}
