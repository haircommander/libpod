package createconfig

import (
	"fmt"
	"os"
	"strings"

	"github.com/containers/libpod/libpod"
	"github.com/docker/docker/oci/caps"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/runtime-tools/generate"
	"github.com/opencontainers/selinux/go-selinux/label"
	"github.com/pkg/errors"
)

func (c *SecurityConfig) ToCreateOptions() ([]libpod.CtrCreateOption, error) {
	options := make([]libpod.CtrCreateOption, 0)
	options = append(options, libpod.WithSecLabels(c.LabelOpts))
	options = append(options, libpod.WithPrivileged(c.Privileged))
	return options, nil
}

func GetSecurityConfig(pidConfig *PidConfig, ipcConfig *IpcConfig, securityOpts []string, runtime *libpod.Runtime, privileged bool) (*SecurityConfig, error) {
	c := &SecurityConfig{
		Privileged: privileged,
	}

	if privileged {
		c.LabelOpts = label.DisableSecOpt()
		return c, nil
	}

	var labelOpts []string
	if pidConfig.PidMode.IsHost() {
		labelOpts = append(labelOpts, label.DisableSecOpt()...)
	} else if pidConfig.PidMode.IsContainer() {
		ctr, err := runtime.LookupContainer(pidConfig.PidMode.Container())
		if err != nil {
			return nil, errors.Wrapf(err, "container %q not found", pidConfig.PidMode.Container())
		}
		secopts, err := label.DupSecOpt(ctr.ProcessLabel())
		if err != nil {
			return nil, errors.Wrapf(err, "failed to duplicate label %q ", ctr.ProcessLabel())
		}
		labelOpts = append(labelOpts, secopts...)
	}

	if ipcConfig.IpcMode.IsHost() {
		labelOpts = append(labelOpts, label.DisableSecOpt()...)
	} else if ipcConfig.IpcMode.IsContainer() {
		ctr, err := runtime.LookupContainer(ipcConfig.IpcMode.Container())
		if err != nil {
			return nil, errors.Wrapf(err, "container %q not found", ipcConfig.IpcMode.Container())
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

func (c *SecurityConfig) ConfigureGenerator(g *generate.Generator, user *UserConfig, configSpec *spec.Spec) error {
	// HANDLE CAPABILITIES
	// NOTE: Must happen before SECCOMP
	if c.Privileged {
		g.SetupPrivileged(true)
	}

	useNotRoot := func(user string) bool {
		if user == "" || user == "root" || user == "0" {
			return false
		}
		return true
	}

	var err error
	var caplist []string
	bounding := configSpec.Process.Capabilities.Bounding
	if useNotRoot(user.User) {
		configSpec.Process.Capabilities.Bounding = caplist
	}
	caplist, err = caps.TweakCapabilities(configSpec.Process.Capabilities.Bounding, c.CapAdd, c.CapDrop, nil, false)
	if err != nil {
		return err
	}

	configSpec.Process.Capabilities.Bounding = caplist
	configSpec.Process.Capabilities.Permitted = caplist
	configSpec.Process.Capabilities.Inheritable = caplist
	configSpec.Process.Capabilities.Effective = caplist
	configSpec.Process.Capabilities.Ambient = caplist
	if useNotRoot(user.User) {
		caplist, err = caps.TweakCapabilities(bounding, c.CapAdd, c.CapDrop, nil, false)
		if err != nil {
			return err
		}
	}
	configSpec.Process.Capabilities.Bounding = caplist

	// HANDLE SECCOMP
	if c.SeccompProfilePath != "unconfined" {
		seccompConfig, err := getSeccompConfig(c, configSpec)
		if err != nil {
			return err
		}
		configSpec.Linux.Seccomp = seccompConfig
	}

	// Clear default Seccomp profile from Generator for privileged containers
	if c.SeccompProfilePath == "unconfined" || c.Privileged {
		configSpec.Linux.Seccomp = nil
	}

	for _, opt := range c.SecurityOpts {
		// Split on both : and =
		splitOpt := strings.Split(opt, "=")
		if len(splitOpt) == 1 {
			splitOpt = strings.Split(opt, ":")
		}
		if len(splitOpt) < 2 {
			continue
		}
		switch splitOpt[0] {
		case "label":
			configSpec.Annotations[libpod.InspectAnnotationLabel] = splitOpt[1]
		case "seccomp":
			configSpec.Annotations[libpod.InspectAnnotationSeccomp] = splitOpt[1]
		case "apparmor":
			configSpec.Annotations[libpod.InspectAnnotationApparmor] = splitOpt[1]
		}
	}

	g.SetRootReadonly(c.ReadOnlyRootfs)
	for sysctlKey, sysctlVal := range c.Sysctl {
		g.AddLinuxSysctl(sysctlKey, sysctlVal)
	}

	return nil
}
