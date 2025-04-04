package containerdiscovery

import (
	"strconv"
	"strings"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

const (
	defaultSocket = "/var/run/podman/podman.sock"
	defaultLabel  = "coredns"
)

type config struct {
	socketPath       string
	exposeByDefault  bool
	label            string
	network          string
	baseDomain       string
	useContainerName bool
	useHostName      bool
}

func defaultConfig() *config {
	return &config{
		socketPath: defaultSocket,
		label:      defaultLabel,
	}
}

func init() { plugin.Register(pluginName, setup) }

func setup(c *caddy.Controller) error {
	config, err := parse(c)
	if err != nil {
		return plugin.Error(pluginName, err)
	}

	cl, err := newContainerLabel(
		config.socketPath,
		config.exposeByDefault,
		config.label,
		config.network,
		config.baseDomain,
		config.useContainerName,
		config.useHostName,
	)
	if err != nil {
		return err
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		c.OnStartup(cl.OnStartup)
		c.OnShutdown(cl.OnShutdown)
		cl.Next = next
		return cl
	})

	return nil
}

func stringArg(c *caddy.Controller) (string, error) {
	if !c.NextArg() {
		return "", c.ArgErr()
	}
	return c.Val(), nil
}

func boolArg(c *caddy.Controller) (bool, error) {
	key := c.Val()
	if c.NextArg() {
		arg, err := strconv.ParseBool(c.Val())
		if err != nil {
			return false, c.Errf("%q: expected boolean, got %q", key, c.Val())
		}
		return arg, nil
	}
	return true, nil
}

func parse(c *caddy.Controller) (*config, error) {
	config := defaultConfig()

	var err error
	for c.Next() {
		args := c.RemainingArgs()
		if len(args) > 1 {
			return nil, c.ArgErr()
		}

		if len(args) == 1 {
			config.socketPath = args[0]
		}

		for c.NextBlock() {
			switch strings.ToLower(c.Val()) {
			case "exposebydefault":
				if config.exposeByDefault, err = boolArg(c); err != nil {
					return nil, err
				}

			case "label":
				if config.label, err = stringArg(c); err != nil {
					return nil, err
				}

			case "network":
				if config.network, err = stringArg(c); err != nil {
					return nil, err
				}

			case "basedomain":
				if config.baseDomain, err = stringArg(c); err != nil {
					return nil, err
				}

			case "usecontainername":
				if config.useContainerName, err = boolArg(c); err != nil {
					return nil, err
				}

			case "usehostname":
				if config.useHostName, err = boolArg(c); err != nil {
					return nil, err
				}

			default:
				return nil, c.Errf("unknown property %q", c.Val())
			}
		}
	}
	return config, nil
}
