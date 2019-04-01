package shared

import (
	"context"
	"strconv"
	"strings"
	"syscall"

	"github.com/containers/libpod/cmd/podman/cliconfig"
	"github.com/containers/libpod/libpod"
	"github.com/containers/libpod/libpod/image"
	cc "github.com/containers/libpod/pkg/spec"
	"github.com/containers/libpod/pkg/util"
	"github.com/cri-o/ocicni/pkg/ocicni"
	"github.com/docker/go-connections/nat"
	"github.com/pkg/errors"
)

const (
	stopped = "Stopped"
	running = "Running"
	paused  = "Paused"
	exited  = "Exited"
	errored = "Error"
	created = "Created"
)

// GetPodStatus determines the status of the pod based on the
// statuses of the containers in the pod.
// Returns a string representation of the pod status
func GetPodStatus(pod *libpod.Pod) (string, error) {
	ctrStatuses, err := pod.Status()
	if err != nil {
		return errored, err
	}
	return CreatePodStatusResults(ctrStatuses)
}

func CreatePodStatusResults(ctrStatuses map[string]libpod.ContainerStatus) (string, error) {
	ctrNum := len(ctrStatuses)
	if ctrNum == 0 {
		return created, nil
	}
	statuses := map[string]int{
		stopped: 0,
		running: 0,
		paused:  0,
		created: 0,
		errored: 0,
	}
	for _, ctrStatus := range ctrStatuses {
		switch ctrStatus {
		case libpod.ContainerStateExited:
			fallthrough
		case libpod.ContainerStateStopped:
			statuses[stopped]++
		case libpod.ContainerStateRunning:
			statuses[running]++
		case libpod.ContainerStatePaused:
			statuses[paused]++
		case libpod.ContainerStateCreated, libpod.ContainerStateConfigured:
			statuses[created]++
		default:
			statuses[errored]++
		}
	}

	if statuses[running] > 0 {
		return running, nil
	} else if statuses[paused] == ctrNum {
		return paused, nil
	} else if statuses[stopped] == ctrNum {
		return exited, nil
	} else if statuses[stopped] > 0 {
		return stopped, nil
	} else if statuses[errored] > 0 {
		return errored, nil
	}
	return created, nil
}

// GetNamespaceOptions transforms a slice of kernel namespaces
// into a slice of pod create options. Currently, not all
// kernel namespaces are supported, and they will be returned in an error
func GetNamespaceOptions(ns []string) ([]libpod.PodCreateOption, error) {
	var options []libpod.PodCreateOption
	var erroredOptions []libpod.PodCreateOption
	for _, toShare := range ns {
		switch toShare {
		case "cgroup":
			options = append(options, libpod.WithPodCgroups())
		case "net":
			options = append(options, libpod.WithPodNet())
		case "mnt":
			return erroredOptions, errors.Errorf("Mount sharing functionality not supported on pod level")
		case "pid":
			options = append(options, libpod.WithPodPID())
		case "user":
			return erroredOptions, errors.Errorf("User sharing functionality not supported on pod level")
		case "ipc":
			options = append(options, libpod.WithPodIPC())
		case "uts":
			options = append(options, libpod.WithPodUTS())
		case "":
		case "none":
			return erroredOptions, nil
		default:
			return erroredOptions, errors.Errorf("Invalid kernel namespace to share: %s. Options are: net, pid, ipc, uts or none", toShare)
		}
	}
	return options, nil
}

// CreatePortBindings iterates ports mappings and exposed ports into a format CNI understands
func CreatePortBindings(ports []string) ([]ocicni.PortMapping, error) {
	var portBindings []ocicni.PortMapping
	// The conversion from []string to natBindings is temporary while mheon reworks the port
	// deduplication code.  Eventually that step will not be required.
	_, natBindings, err := nat.ParsePortSpecs(ports)
	if err != nil {
		return nil, err
	}
	for containerPb, hostPb := range natBindings {
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

func ParseInfraCreateOpts(ctx context.Context, c *cliconfig.PodCreateValues, runtime *libpod.Runtime) (*cc.CreateConfig, error) {
	newImage, err := runtime.ImageRuntime().New(ctx, c.InfraImage, "", "", nil, nil, image.SigningOptions{}, false, nil)
	if err != nil {
		return nil, err
	}

	data, err := newImage.Inspect(ctx)
	if err != nil {
		return nil, err
	}
	imageName := newImage.Names()[0]
	imageID := data.ID

	entry := make([]string, 0)
	cmd := make([]string, 0)
	setEntrypoint := false

	env := defaultEnvVariables
	// I've seen circumstances where data.Config is being passed as nil.
	// Let's err on the side of safety and make sure it's safe to use.
	if data.Config != nil {
		// default to entrypoint in image if there is one
		if len(data.Config.Entrypoint) > 0 && !setEntrypoint {
			entry = data.Config.Entrypoint
			setEntrypoint = true
		}
		if len(data.Config.Cmd) > 0 {
			// We can't use the default pause command, since we're
			// sourcing from the image. If we didn't already set an
			// entrypoint, set one now.
			if !setEntrypoint {
				// Use the Docker default "/bin/sh -c"
				// entrypoint, as we're overriding command.
				// If an image doesn't want this, it can
				// override entrypoint too.
				entry = []string{"/bin/sh", "-c"}
			}
			cmd = append(cmd, data.Config.Cmd...)
		}

		for _, e := range data.Config.Env {
			split := strings.SplitN(e, "=", 2)
			if len(split) > 1 {
				env[split[0]] = split[1]
			} else {
				env[split[0]] = ""
			}
		}
	}

	// Override Infra command if passed in by user
	if len(c.InfraCommand) > 0 {
		// TODO FIXME InfraCommand is a string right now..
		cmd = []string{c.InfraCommand}
	}

	// I think?
	//var portBindings map[nat.Port][]nat.PortBinding
	//if len(c.Publish) > 0 {
	//	portBindings, err := CreatePortBindings(c.Publish)
	//	if err != nil {
	//		return nil, err
	//	}
	//}

	var portBindings map[nat.Port][]nat.PortBinding
	if data != nil {
		portBindings, err = cc.ExposedPorts(c.StringSlice("expose"), c.StringSlice("publish"), c.Bool("publish-all"), data.Config.ExposedPorts)
		if err != nil {
			return nil, err
		}
	}

	idmappings, err := util.ParseIDMapping([]string{}, []string{}, "", "")
	if err != nil {
		return nil, errors.Wrapf(err, "Problem making empty IDMapping slice")
	}

	workDir := "/"
	// TODO move
	if data != nil && data.Config.WorkingDir != "" {
		workDir = data.Config.WorkingDir
	}

	config := &cc.CreateConfig{
		Runtime: runtime,
		//Annotations:       annotations, TODO
		//BuiltinImgVolumes: ImageVolumes, TODO
		//ConmonPidFile:     c.String("conmon-pidfile"), TODO
		ImageVolumeType: "ignore",
		CgroupParent:    c.String("cgroup-parent"),
		Command:         cmd,
		//Devices:           c.StringSlice("device"), // TODO
		Entrypoint: entry, // TODO
		Env:        env,
		//ExposedPorts:   ports,
		//GroupAdd:    c.StringSlice("group-add"), // TODO
		//Hostname:    c.String("hostname"), // TODO
		//HostAdd:     c.StringSlice("add-host"), // TODO
		//NoHosts:     c.Bool("no-hosts"), // TODO
		IDMappings: idmappings,
		Image:      imageName,
		ImageID:    imageID,
		//Interactive: c.Bool("interactive"), // TODO
		//IPAddress: c.String("ip"), // TODO
		//Labels:    labels, // TODO
		//LogDriver:    c.String("log-driver"), // TODO
		//LogDriverOpt: c.StringSlice("log-opt"), // TODO
		//MacAddress:   c.String("mac-address"), // TODO
		//Name:         c.String("name"), // TODO
		//// TODO figure out NS
		//Network:      network, // TODO
		//IpcMode:        ipcMode, // TODO
		//NetMode:        netMode, // TODO
		//UtsMode:        utsMode, // TODO
		//PidMode:        pidMode, // TODO
		Pod:        "", // We will add the pod once the pod is actually created
		Privileged: false,
		//Publish:        c.StringSlice("publish"), // TODO
		//PublishAll:     c.Bool("publish-all"), // TODO
		PortBindings: portBindings,
		//Quiet:          false, // TODO
		//ReadOnlyRootfs: false, // TODO
		//Resources: cc.CreateResourceConfig{ // TODO
		//BlkioWeight:       blkioWeight, // TODO
		//BlkioWeightDevice: c.StringSlice("blkio-weight-device"), // TODO
		//CPUShares:         c.Uint64("cpu-shares"), // TODO
		//CPUPeriod:         c.Uint64("cpu-period"), // TODO
		//CPUsetCPUs:        c.String("cpuset-cpus"), // TODO
		//CPUsetMems:        c.String("cpuset-mems"), // TODO
		//CPUQuota:          c.Int64("cpu-quota"), // TODO
		//CPURtPeriod:       c.Uint64("cpu-rt-period"), // TODO
		//CPURtRuntime:      c.Int64("cpu-rt-runtime"), // TODO
		//CPUs:              c.Float64("cpus"), // TODO
		//DeviceReadBps:     c.StringSlice("device-read-bps"), // TODO
		//DeviceReadIOps:    c.StringSlice("device-read-iops"), // TODO
		//DeviceWriteBps:    c.StringSlice("device-write-bps"), // TODO
		//DeviceWriteIOps:   c.StringSlice("device-write-iops"), // TODO
		//DisableOomKiller:  c.Bool("oom-kill-disable"), // TODO
		//ShmSize:           shmSize, // TODO
		//Memory:            memoryLimit, // TODO
		//MemoryReservation: memoryReservation, // TODO
		//MemorySwap:        memorySwap, // TODO
		//MemorySwappiness:  int(memorySwappiness), // TODO
		//KernelMemory:      memoryKernel, // TODO
		//OomScoreAdj:       c.Int("oom-score-adj"), // TODO
		//PidsLimit:         c.Int64("pids-limit"), // TODO
		//Ulimit:            c.StringSlice("ulimit"), // TODO
		//},
		//Rm:          c.Bool("rm"), // TODO
		StopSignal: syscall.SIGTERM,
		//StopTimeout: c.Uint("stop-timeout"), // TODO
		//Sysctl:      sysctl, // TODO
		//Systemd:     systemd, // TODO
		//Tmpfs:       c.StringSlice("tmpfs"), // TODO
		//Tty:         tty, // TODO
		//User:        user, // TODO
		//UsernsMode:  usernsMode, // TODO
		//Mounts:      mountList, // TODO
		//Volumes:     c.StringArray("volume"), // TODO
		WorkDir: workDir, // TODO
		//Rootfs:      rootfs, // TODO
		//VolumesFrom: c.StringSlice("volumes-from"), // TODO
		//Syslog:      c.GlobalFlags.Syslog, // TODO
	}

	// TODO FIXME do we wnat htis
	//warnings, err := verifyContainerResources(config, false)
	//if err != nil {
	//	return nil, err
	//}
	//for _, warning := range warnings {
	//	fmt.Fprintln(os.Stderr, warning)
	//}
	return config, nil
}

var DefaultKernelNamespaces = "cgroup,ipc,net,uts"
