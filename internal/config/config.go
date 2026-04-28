package config

const (
	ProductName           = "RunBrake"
	LocalEnvironment      = "local"
	DefaultSidecarAddress = "127.0.0.1:47838"
)

type Config struct {
	ProductName    string
	Environment    string
	SidecarAddress string
}

func Default() Config {
	return Config{
		ProductName:    ProductName,
		Environment:    LocalEnvironment,
		SidecarAddress: DefaultSidecarAddress,
	}
}
