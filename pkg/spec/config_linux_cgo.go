// +build linux,cgo

package createconfig

import (
	"io/ioutil"

	"github.com/docker/docker/profiles/seccomp"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
)

// TODO FIXME make this take SecurityConfig instead
func getSeccompConfig(config *CreateConfig, configSpec *spec.Spec) (*spec.LinuxSeccomp, error) {
	var seccompConfig *spec.LinuxSeccomp
	var err error

	if config.Security.SeccompProfilePath != "" {
		seccompProfile, err := ioutil.ReadFile(config.Security.SeccompProfilePath)
		if err != nil {
			return nil, errors.Wrapf(err, "opening seccomp profile (%s) failed", config.Security.SeccompProfilePath)
		}
		seccompConfig, err = seccomp.LoadProfile(string(seccompProfile), configSpec)
		if err != nil {
			return nil, errors.Wrapf(err, "loading seccomp profile (%s) failed", config.Security.SeccompProfilePath)
		}
	} else {
		seccompConfig, err = seccomp.GetDefaultProfile(configSpec)
		if err != nil {
			return nil, errors.Wrapf(err, "loading seccomp profile (%s) failed", config.Security.SeccompProfilePath)
		}
	}

	return seccompConfig, nil
}
