package tlshelper

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func Test_setupCACert(t *testing.T) {
	type args struct {
		certPath    string
		useSystemCA bool
	}

	caPool := x509.NewCertPool()
	caSystemPool, _ := x509.SystemCertPool()

	tests := []struct {
		name    string
		args    args
		want    int
		wantErr bool
	}{
		{
			"case 1",
			args{"", false},
			len(caPool.Subjects()),
			false,
		},
		{
			"case 2",
			args{"test_data/ca.pem", false},
			1,
			false,
		},
		{
			"case 3",
			args{"test_data/ca.pem", true},
			len(caSystemPool.Subjects()) + 1,
			false,
		},
		{
			"case 4",
			args{"", true},
			len(caSystemPool.Subjects()),
			false,
		},
		{
			"case 5",
			args{"test_data/ca2.pem", false},
			0,
			true,
		},
		{
			"case 6",
			args{"test_data/cert.csr", false},
			0,
			true,
		},
		{
			"case 7",
			args{"test_data/ca2.pem", true},
			len(caSystemPool.Subjects()),
			true,
		},
		{
			"case 8",
			args{"test_data/cert.crt", true},
			len(caSystemPool.Subjects()) + 1,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &tls.Config{}
			err := setupCACert(&cfg.ClientCAs, tt.args.certPath, tt.args.useSystemCA)
			if (err != nil) != tt.wantErr {
				t.Errorf("setupCACert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got := len(cfg.ClientCAs.Subjects()); got != tt.want {
				t.Errorf("setupCACert() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_setupCertificate(t *testing.T) {
	type args struct {
		required    bool
		certPath    string
		certKeyPath string
		certKeyPass string
	}
	tests := []struct {
		name    string
		args    args
		want    int
		wantErr bool
	}{
		{
			"case 1",
			args{false, "", "", ""},
			0,
			false,
		},
		{
			"case 2",
			args{true, "", "", ""},
			0,
			true,
		},
		{
			"case 3",
			args{true, "test_data/cert.crt", "test_data/cert.key", ""},
			1,
			false,
		},
		{
			"case 4",
			args{true, "test_data/cert.crt", "test_data/cert.key", ""},
			1,
			false,
		},
		{
			"case 5",
			args{false, "test_data/cert_pass.crt", "test_data/cert_pass.key", "test"},
			1,
			false,
		},
		{
			"case 6",
			args{true, "test_data/cert_pass.crt", "test_data/cert_pass.key", "test"},
			1,
			false,
		},
		{
			"case 7",
			args{false, "test_data/cert_pass.crt", "test_data/cert_pass.key", "test1"},
			0,
			true,
		},
		{
			"case 8",
			args{true, "test_data/cert2.crt", "test_data/cert.key", ""},
			0,
			true,
		},
		{
			"case 9",
			args{true, "test_data/cert.crt", "test_data/cert2.key", ""},
			0,
			true,
		},
		{
			"case 10",
			args{true, "test_data/cert.crt", "test_data/cert.key", "ignored_password"},
			1,
			false,
		},
		{
			"case 11",
			args{true, "test_data/cert_pass2.crt", "test_data/cert_pass.key", "test"},
			0,
			true,
		},
		{
			"case 11",
			args{true, "test_data/cert_pass.crt", "test_data/cert_pass2.key", "test"},
			0,
			true,
		},
		{
			"case 12",
			args{true, "test_data/cert_signed.crt", "test_data/cert.key", ""},
			1,
			false,
		},
		{
			"case 13",
			args{true, "test_data/cert_pass_signed.crt", "test_data/cert_pass.key", "test"},
			1,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &tls.Config{}
			if err := setupCertificate(cfg, tt.args.required, tt.args.certPath, tt.args.certKeyPath, tt.args.certKeyPass); (err != nil) != tt.wantErr {
				t.Errorf("setupCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got := len(cfg.Certificates); got != tt.want {
				t.Errorf("setupCACert() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_setupTlsVersion(t *testing.T) {
	type args struct {
		minVersion string
		maxVersion string
	}
	tests := []struct {
		name    string
		args    args
		min     uint16
		max     uint16
		wantErr bool
	}{
		{
			name:    "case 1",
			args:    args{"", ""},
			min:     tls.VersionTLS11,
			max:     tls.VersionTLS12,
			wantErr: false,
		},
		{
			name:    "case 2",
			args:    args{"test", ""},
			min:     0,
			max:     0,
			wantErr: true,
		},
		{
			name:    "case 3",
			args:    args{"", "test"},
			min:     tls.VersionTLS11,
			max:     0,
			wantErr: true,
		},
		{
			name:    "case 4",
			args:    args{"TLS11", "test"},
			min:     tls.VersionTLS11,
			max:     0,
			wantErr: true,
		},
		{
			name:    "case 5",
			args:    args{"test", "TLS12"},
			min:     0,
			max:     0,
			wantErr: true,
		},
		{
			name:    "case 6",
			args:    args{"TLS11", "TLS12"},
			min:     tls.VersionTLS11,
			max:     tls.VersionTLS12,
			wantErr: false,
		},
		{
			name:    "case 7",
			args:    args{"Tls11", "TLS12"},
			min:     tls.VersionTLS11,
			max:     tls.VersionTLS12,
			wantErr: false,
		},
		{
			name:    "case 8",
			args:    args{"TLS11", "Tls12"},
			min:     tls.VersionTLS11,
			max:     tls.VersionTLS12,
			wantErr: false,
		},
		{
			name:    "case 9",
			args:    args{"TLS12", "TlS11"},
			min:     tls.VersionTLS12,
			max:     0,
			wantErr: true,
		},
		{
			name:    "case 10",
			args:    args{"TLS12", "TlS12"},
			min:     tls.VersionTLS12,
			max:     tls.VersionTLS12,
			wantErr: false,
		},
		{
			name:    "case 11",
			args:    args{"TLS11", "TlS11"},
			min:     tls.VersionTLS11,
			max:     tls.VersionTLS11,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &tls.Config{}
			if err := setupVersion(cfg, tt.args.minVersion, tt.args.maxVersion); (err != nil) != tt.wantErr {
				t.Errorf("setupTlsVersion() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.min != cfg.MinVersion || cfg.MaxVersion != tt.max {
				t.Errorf("setupTlsVersion() expected [%v, %v], obtaint [%v, %v]", tt.min, tt.max, cfg.MinVersion, cfg.MaxVersion)
			}
		})
	}
}
