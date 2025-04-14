package containerdiscovery

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

const (
	defaultSocket = "unix:///var/run/podman/podman.sock"
	defaultLabel  = "coredns"
)

type config struct {
	endpoint         string
	exposeByDefault  bool
	labelPrefix      string
	network          string
	baseDomain       string
	useContainerName bool
	useHostName      bool
}

func defaultConfig() *config {
	return &config{
		endpoint:         defaultSocket,
		labelPrefix:      defaultLabel,
		useContainerName: true,
	}
}

func init() { plugin.Register(pluginName, setup) }

func setup(c *caddy.Controller) error {
	config, err := parse(c)
	if err != nil {
		return plugin.Error(pluginName, err)
	}

	cl := newContainerDiscovery(config)
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		cl.Next = next
		return cl
	})

	c.OnStartup(func() error {
		return cl.OnStartup()
	})

	c.OnShutdown(func() error {
		return cl.OnShutdown()
	})

	return nil
}

func stringArg(c *caddy.Controller) (string, error) {
	key := c.Val()
	if !c.NextArg() {
		return "", c.ArgErr()
	}
	if len(c.Val()) == 0 {
		return "", c.Errf("expected value for %q", key)
	}
	return c.Val(), nil
}

func boolArg(c *caddy.Controller) (bool, error) {
	if c.NextArg() {
		arg, err := strconv.ParseBool(c.Val())
		if err != nil {
			return false, c.SyntaxErr("boolean")
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
			url, err := url.Parse(args[0])
			if err != nil {
				return nil, err
			}

			if !url.IsAbs() {
				return nil, c.Err("invalid endpoint url")
			}
			config.endpoint = args[0]
		}

		for c.NextBlock() {
			switch strings.ToLower(c.Val()) {
			case "exposebydefault":
				if config.exposeByDefault, err = boolArg(c); err != nil {
					return nil, err
				}

			case "label":
				labelPrefix, err := stringArg(c)
				if err != nil {
					return nil, err
				}

				if len(labelPrefix) < 3 || len(labelPrefix) > 30 {
					return nil, c.Err("label length must be between 3 and 30 characters")
				}

				pattern := regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
				if !pattern.MatchString(labelPrefix) {
					return nil, c.Err("invalid character in labelPrefix")
				}
				config.labelPrefix = labelPrefix

			case "basedomain":
				baseDomain, err := stringArg(c)
				if err != nil {
					return nil, err
				}

				if _, ok := dns.IsDomainName(baseDomain); !ok {
					return nil, c.Errf("invalid baseDomain %q", baseDomain)
				}
				config.baseDomain = baseDomain

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
