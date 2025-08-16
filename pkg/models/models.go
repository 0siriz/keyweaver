package	models

type CAConfig struct {
	OutputDirectory string               `mapstructure:"output_dir"`
	CAs				map[string]CADetails `mapstructure:"cas"`
}

type CADetails struct {
	CommonName   string               `mapstructure:"common_name"`
	Organization string               `mapstructure:"organization"`
	Country      string               `mapstructure:"country"`
	ValidityDays int                  `mapstructure:"validity_days"`
	IssuedCAs    map[string]CADetails `mapstructure:"issued_cas,omitempty"`
}
