package createconfig

import (
	"fmt"
	"os"
	"strings"

	"github.com/containers/libpod/libpod"
	"github.com/opencontainers/selinux/go-selinux/label"
	"github.com/pkg/errors"
)

func (c *SecurityConfig) configureSecurity() ([]libpod.CtrCreateOption, error) {
	options := make([]libpod.CtrCreateOption, 0)
	options = append(options, libpod.WithPrivileged(c.Privileged))
	return options, nil
}

func GetSecurityConfig(nsConfig *NamespaceConfig, securityOpts []string, runtime *libpod.Runtime, privileged bool) (*SecurityConfig, error) {
	c := &SecurityConfig{
		Privileged: privileged,
	}

	if privileged {
		c.LabelOpts = label.DisableSecOpt()
		return c, nil
	}

	var labelOpts []string
	if nsConfig.PidMode.IsHost() {
		labelOpts = append(labelOpts, label.DisableSecOpt()...)
	} else if nsConfig.PidMode.IsContainer() {
		ctr, err := runtime.LookupContainer(nsConfig.PidMode.Container())
		if err != nil {
			return nil, errors.Wrapf(err, "container %q not found", nsConfig.PidMode.Container())
		}
		secopts, err := label.DupSecOpt(ctr.ProcessLabel())
		if err != nil {
			return nil, errors.Wrapf(err, "failed to duplicate label %q ", ctr.ProcessLabel())
		}
		labelOpts = append(labelOpts, secopts...)
	}

	if nsConfig.IpcMode.IsHost() {
		labelOpts = append(labelOpts, label.DisableSecOpt()...)
	} else if nsConfig.IpcMode.IsContainer() {
		ctr, err := runtime.LookupContainer(nsConfig.IpcMode.Container())
		if err != nil {
			return nil, errors.Wrapf(err, "container %q not found", nsConfig.IpcMode.Container())
		}
		secopts, err := label.DupSecOpt(ctr.ProcessLabel())
		if err != nil {
			return nil, errors.Wrapf(err, "failed to duplicate label %q ", ctr.ProcessLabel())
		}
		labelOpts = append(labelOpts, secopts...)
	}

	for _, opt := range securityOpts {
		if opt == "no-new-privileges" {
			c.NoNewPrivs = true
		} else {
			con := strings.SplitN(opt, "=", 2)
			if len(con) != 2 {
				return nil, fmt.Errorf("invalid --security-opt 1: %q", opt)
			}

			switch con[0] {
			case "label":
				labelOpts = append(labelOpts, con[1])
			case "apparmor":
				c.ApparmorProfile = con[1]
			case "seccomp":
				c.SeccompProfilePath = con[1]
			default:
				return nil, fmt.Errorf("invalid --security-opt 2: %q", opt)
			}
		}
	}

	if c.SeccompProfilePath == "" {
		if _, err := os.Stat(libpod.SeccompOverridePath); err == nil {
			c.SeccompProfilePath = libpod.SeccompOverridePath
		} else {
			if !os.IsNotExist(err) {
				return nil, errors.Wrapf(err, "can't check if %q exists", libpod.SeccompOverridePath)
			}
			if _, err := os.Stat(libpod.SeccompDefaultPath); err != nil {
				if !os.IsNotExist(err) {
					return nil, errors.Wrapf(err, "can't check if %q exists", libpod.SeccompDefaultPath)
				}
			} else {
				c.SeccompProfilePath = libpod.SeccompDefaultPath
			}
		}
	}
	c.LabelOpts = labelOpts
	c.SecurityOpts = securityOpts
	return c, nil
}
