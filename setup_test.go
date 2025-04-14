package containerdiscovery

import (
	"testing"

	"github.com/coredns/caddy"
)

func Test_setup(t *testing.T) {
	tests := []struct {
		name    string
		args    string
		wantErr bool
	}{
		{
			"base config",
			`containers`,
			false,
		},
		{
			"no absolute path",
			`containers notAbsolutePath`,
			true,
		},
		{
			"invalid url",
			`containers //invalid url`,
			true,
		},
		{
			"config with options",
			`containers unix:///var/run/user/1000/podman/podman.sock {
					exposeByDefault true
					label coredns.zone1
					baseDomain test.local
					useHostname
				}`,
			false,
		},
		{
			"too many args",
			`containers /path/to/socket andAnotherArg`,
			true,
		},
		{
			"not a boolean",
			`containers {
					exposeByDefault thisIsNotABool
				}`,
			true,
		},
		{
			"missing arg value",
			`containers unix:///path/to/socket {
					label ""
				}`,
			true,
		},
		{
			"unknown arg value",
			`containers unix:///path/to/socket {
					unknown arg
				}`,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tt.args)
			if err := setup(c); (err != nil) != tt.wantErr {
				t.Errorf("setup() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
