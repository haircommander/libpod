package createconfig

import (
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/containers/libpod/libpod"
	"github.com/containers/libpod/libpod/define"
	"github.com/cri-o/ocicni/pkg/ocicni"
	"github.com/docker/go-connections/nat"
	"github.com/pkg/errors"
)

func (c *NamespaceConfig) configureNetNamespace(runtime *libpod.Runtime) ([]libpod.CtrCreateOption, error) {
	var portBindings []ocicni.PortMapping
	var err error
	if len(c.PortBindings) > 0 {
		portBindings, err = c.CreatePortBindings()
		if err != nil {
			return nil, errors.Wrapf(err, "unable to create port bindings")
		}
	}

	options := make([]libpod.CtrCreateOption, 0)
	userNetworks := c.NetMode.UserDefined()
	networks := make([]string, 0)

	if IsPod(userNetworks) {
		userNetworks = ""
	}
	if userNetworks != "" {
		for _, netName := range strings.Split(userNetworks, ",") {
			if netName == "" {
				return nil, errors.Errorf("container networks %q invalid", userNetworks)
			}
			networks = append(networks, netName)
		}
	}

	if c.NetMode.IsNS() {
		ns := c.NetMode.NS()
		if ns == "" {
			return nil, errors.Errorf("invalid empty user-defined network namespace")
		}
		_, err := os.Stat(ns)
		if err != nil {
			return nil, err
		}
	} else if c.NetMode.IsContainer() {
		connectedCtr, err := runtime.LookupContainer(c.NetMode.Container())
		if err != nil {
			return nil, errors.Wrapf(err, "container %q not found", c.NetMode.Container())
		}
		options = append(options, libpod.WithNetNSFrom(connectedCtr))
	} else if !c.NetMode.IsHost() && !c.NetMode.IsNone() {
		hasUserns := c.UsernsMode.IsContainer() || c.UsernsMode.IsNS() || len(c.IDMappings.UIDMap) > 0 || len(c.IDMappings.GIDMap) > 0
		postConfigureNetNS := hasUserns && !c.UsernsMode.IsHost()
		options = append(options, libpod.WithNetNS(portBindings, postConfigureNetNS, string(c.NetMode), networks))
	}

	if len(c.DNSSearch) > 0 {
		options = append(options, libpod.WithDNSSearch(c.DNSSearch))
	}
	if len(c.DNSServers) > 0 {
		if len(c.DNSServers) == 1 && strings.ToLower(c.DNSServers[0]) == "none" {
			options = append(options, libpod.WithUseImageResolvConf())
		} else {
			options = append(options, libpod.WithDNS(c.DNSServers))
		}
	}
	if len(c.DNSOpt) > 0 {
		options = append(options, libpod.WithDNSOption(c.DNSOpt))
	}
	if c.NoHosts {
		options = append(options, libpod.WithUseImageHosts())
	}
	if len(c.HostAdd) > 0 && !c.NoHosts {
		options = append(options, libpod.WithHosts(c.HostAdd))
	}

	if c.IPAddress != "" {
		ip := net.ParseIP(c.IPAddress)
		if ip == nil {
			return nil, errors.Wrapf(define.ErrInvalidArg, "cannot parse %s as IP address", c.IPAddress)
		} else if ip.To4() == nil {
			return nil, errors.Wrapf(define.ErrInvalidArg, "%s is not an IPv4 address", c.IPAddress)
		}
		options = append(options, libpod.WithStaticIP(ip))
	}

	return options, nil
}

// CreatePortBindings iterates ports mappings and exposed ports into a format CNI understands
func (c *NamespaceConfig) CreatePortBindings() ([]ocicni.PortMapping, error) {
	return NatToOCIPortBindings(c.PortBindings)
}

// NatToOCIPortBindings iterates a nat.portmap slice and creates []ocicni portmapping slice
func NatToOCIPortBindings(ports nat.PortMap) ([]ocicni.PortMapping, error) {
	var portBindings []ocicni.PortMapping
	for containerPb, hostPb := range ports {
		var pm ocicni.PortMapping
		pm.ContainerPort = int32(containerPb.Int())
		for _, i := range hostPb {
			var hostPort int
			var err error
			pm.HostIP = i.HostIP
			if i.HostPort == "" {
				hostPort = containerPb.Int()
			} else {
				hostPort, err = strconv.Atoi(i.HostPort)
				if err != nil {
					return nil, errors.Wrapf(err, "unable to convert host port to integer")
				}
			}

			pm.HostPort = int32(hostPort)
			pm.Protocol = containerPb.Proto()
			portBindings = append(portBindings, pm)
		}
	}
	return portBindings, nil
}

func (c *NamespaceConfig) configureCgroupNamespace(runtime *libpod.Runtime) ([]libpod.CtrCreateOption, error) {
	options := make([]libpod.CtrCreateOption, 0)
	if c.CgroupMode.IsNS() {
		ns := c.CgroupMode.NS()
		if ns == "" {
			return nil, errors.Errorf("invalid empty user-defined network namespace")
		}
		_, err := os.Stat(ns)
		if err != nil {
			return nil, err
		}
	} else if c.CgroupMode.IsContainer() {
		connectedCtr, err := runtime.LookupContainer(c.CgroupMode.Container())
		if err != nil {
			return nil, errors.Wrapf(err, "container %q not found", c.CgroupMode.Container())
		}
		options = append(options, libpod.WithCgroupNSFrom(connectedCtr))
	}

	if c.CgroupParent != "" {
		options = append(options, libpod.WithCgroupParent(c.CgroupParent))
	}

	if c.Cgroups == "disabled" {
		options = append(options, libpod.WithNoCgroups())
	}

	return options, nil
}

func (c *NamespaceConfig) configureUserNamespace(runtime *libpod.Runtime) ([]libpod.CtrCreateOption, error) {
	options := make([]libpod.CtrCreateOption, 0)
	if c.UsernsMode.IsNS() {
		ns := c.UsernsMode.NS()
		if ns == "" {
			return nil, errors.Errorf("invalid empty user-defined user namespace")
		}
		_, err := os.Stat(ns)
		if err != nil {
			return nil, err
		}
		options = append(options, libpod.WithIDMappings(*c.IDMappings))
	} else if c.UsernsMode.IsContainer() {
		connectedCtr, err := runtime.LookupContainer(c.UsernsMode.Container())
		if err != nil {
			return nil, errors.Wrapf(err, "container %q not found", c.UsernsMode.Container())
		}
		options = append(options, libpod.WithUserNSFrom(connectedCtr))
	} else {
		options = append(options, libpod.WithIDMappings(*c.IDMappings))
	}

	options = append(options, libpod.WithUser(c.User))
	options = append(options, libpod.WithGroups(c.GroupAdd))

	return options, nil
}

func (c *NamespaceConfig) configurePidNamespace(runtime *libpod.Runtime) ([]libpod.CtrCreateOption, error) {
	options := make([]libpod.CtrCreateOption, 0)
	if c.PidMode.IsContainer() {
		connectedCtr, err := runtime.LookupContainer(c.PidMode.Container())
		if err != nil {
			return nil, errors.Wrapf(err, "container %q not found", c.PidMode.Container())
		}

		options = append(options, libpod.WithPIDNSFrom(connectedCtr))
	}

	return options, nil
}

func (c *NamespaceConfig) configureIpcNamespace(runtime *libpod.Runtime) ([]libpod.CtrCreateOption, error) {
	options := make([]libpod.CtrCreateOption, 0)
	if c.IpcMode.IsContainer() {
		connectedCtr, err := runtime.LookupContainer(c.IpcMode.Container())
		if err != nil {
			return nil, errors.Wrapf(err, "container %q not found", c.IpcMode.Container())
		}

		options = append(options, libpod.WithIPCNSFrom(connectedCtr))
	}

	return options, nil
}

func (c *NamespaceConfig) configureUtsNamespace(runtime *libpod.Runtime, pod *libpod.Pod) ([]libpod.CtrCreateOption, error) {
	options := make([]libpod.CtrCreateOption, 0)
	if IsPod(string(c.UtsMode)) {
		options = append(options, libpod.WithUTSNSFromPod(pod))
	}
	if c.UtsMode.IsContainer() {
		connectedCtr, err := runtime.LookupContainer(c.UtsMode.Container())
		if err != nil {
			return nil, errors.Wrapf(err, "container %q not found", c.UtsMode.Container())
		}

		options = append(options, libpod.WithUTSNSFrom(connectedCtr))
	}

	return options, nil
}
