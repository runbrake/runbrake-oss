package config

import "testing"

func TestDefaultConfigIdentifiesRunBrake(t *testing.T) {
	cfg := Default()

	if cfg.ProductName != "RunBrake" {
		t.Fatalf("ProductName = %q, want RunBrake", cfg.ProductName)
	}

	if cfg.Environment != "local" {
		t.Fatalf("Environment = %q, want local", cfg.Environment)
	}

	if cfg.SidecarAddress != "127.0.0.1:47838" {
		t.Fatalf("SidecarAddress = %q, want 127.0.0.1:47838", cfg.SidecarAddress)
	}
}
