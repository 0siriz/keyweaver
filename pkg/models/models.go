package	models

type CAConfig struct {
	OutputDir string               `mapstructure:"output_dir"`
	CAs       map[string]CADetails `mapstructure:"cas"`
}

type CADetails struct {
	CommonName   string               `mapstructure:"common_name"`
	Organization string               `mapstructure:"organization"`
	Country      string               `mapstructure:"country"`
	ValidityDays int                  `mapstructure:"validity_days"`
	KeyType      string               `mapstructure:"key_type,omitempty"`
	KeySize      int                  `mapstructure:"key_size,omitempty"`
	IssuedCAs    map[string]CADetails `mapstructure:"issued_cas,omitempty"`
}
