package createconfig

import (
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/containers/image/v4/manifest"
	"github.com/containers/libpod/libpod"
	"github.com/containers/libpod/libpod/define"
	"github.com/containers/libpod/pkg/namespaces"
	"github.com/containers/storage"
	"github.com/docker/go-connections/nat"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/runtime-tools/generate"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Type constants
const (
	bps = iota
	iops
)

// CreateResourceConfig represents resource elements in CreateConfig
// structures
type CreateResourceConfig struct {
	BlkioWeight       uint16   // blkio-weight
	BlkioWeightDevice []string // blkio-weight-device
	CPUPeriod         uint64   // cpu-period
	CPUQuota          int64    // cpu-quota
	CPURtPeriod       uint64   // cpu-rt-period
	CPURtRuntime      int64    // cpu-rt-runtime
	CPUShares         uint64   // cpu-shares
	CPUs              float64  // cpus
	CPUsetCPUs        string
	CPUsetMems        string   // cpuset-mems
	DeviceReadBps     []string // device-read-bps
	DeviceReadIOps    []string // device-read-iops
	DeviceWriteBps    []string // device-write-bps
	DeviceWriteIOps   []string // device-write-iops
	DisableOomKiller  bool     // oom-kill-disable
	KernelMemory      int64    // kernel-memory
	Memory            int64    //memory
	MemoryReservation int64    // memory-reservation
	MemorySwap        int64    //memory-swap
	MemorySwappiness  int      // memory-swappiness
	OomScoreAdj       int      //oom-score-adj
	PidsLimit         int64    // pids-limit
	ShmSize           int64
	Ulimit            []string //ulimit
}

type NamespaceConfig struct {
	Cgroups      string
	Cgroupns     string
	CgroupParent string   // cgroup-parent
	DNSOpt       []string //dns-opt
	DNSSearch    []string //dns-search
	DNSServers   []string //dns
	ExposedPorts map[nat.Port]struct{}
	NoHosts      bool
	HostAdd      []string //add-host
	Hostname     string   //hostname
	HTTPProxy    bool
	IDMappings   *storage.IDMappingOptions
	IpcMode      namespaces.IpcMode     //ipc
	IP6Address   string                 //ipv6
	IPAddress    string                 //ip
	GroupAdd     []string               // group-add
	LinkLocalIP  []string               // link-local-ip
	MacAddress   string                 //mac-address
	NetMode      namespaces.NetworkMode //net
	Network      string                 //network
	NetworkAlias []string               //network-alias
	PidMode      namespaces.PidMode     //pid
	PortBindings nat.PortMap
	Publish      []string              //publish
	PublishAll   bool                  //publish-all
	CgroupMode   namespaces.CgroupMode //cgroup
	UsernsMode   namespaces.UsernsMode //userns
	User         string                //user
	UtsMode      namespaces.UTSMode    //uts
}

type SecurityConfig struct {
	CapAdd             []string // cap-add
	CapDrop            []string // cap-drop
	LabelOpts          []string //SecurityOpts
	NoNewPrivs         bool     //SecurityOpts
	ApparmorProfile    string   //SecurityOpts
	SeccompProfilePath string   //SecurityOpts
	SecurityOpts       []string
	Privileged         bool //privileged
	ReadOnlyRootfs     bool //read-only
	ReadOnlyTmpfs      bool //read-only-tmpfs
}

// CreateConfig is a pre OCI spec structure.  It represents user input from varlink or the CLI
type CreateConfig struct {
	Annotations       map[string]string
	Args              []string
	CidFile           string
	ConmonPidFile     string
	Command           []string          // Full command that will be used
	UserCommand       []string          // User-entered command (or image CMD)
	Detach            bool              // detach
	Devices           []string          // device
	Entrypoint        []string          //entrypoint
	Env               map[string]string //env
	HealthCheck       *manifest.Schema2HealthConfig
	Init              bool   // init
	InitPath          string //init-path
	Image             string
	ImageID           string
	BuiltinImgVolumes map[string]struct{} // volumes defined in the image config
	ImageVolumeType   string              // how to handle the image volume, either bind, tmpfs, or ignore
	Interactive       bool                //interactive
	Labels            map[string]string   //label
	LogDriver         string              // log-driver
	LogDriverOpt      []string            // log-opt
	Name              string              //name
	Namespaces        NamespaceConfig
	PodmanPath        string
	Pod               string //pod
	Quiet             bool   //quiet
	Resources         CreateResourceConfig
	RestartPolicy     string
	Rm                bool              //rm
	StopSignal        syscall.Signal    // stop-signal
	StopTimeout       uint              // stop-timeout
	Sysctl            map[string]string //sysctl
	Systemd           bool
	Tmpfs             []string // tmpfs
	Tty               bool     //tty
	Mounts            []spec.Mount
	MountsFlag        []string // mounts
	NamedVolumes      []*libpod.ContainerNamedVolume
	Volumes           []string //volume
	VolumesFrom       []string
	WorkDir           string //workdir
	Rootfs            string
	Security          SecurityConfig
	Syslog            bool // Whether to enable syslog on exit commands
}

func u32Ptr(i int64) *uint32     { u := uint32(i); return &u }
func fmPtr(i int64) *os.FileMode { fm := os.FileMode(i); return &fm }

// CreateBlockIO returns a LinuxBlockIO struct from a CreateConfig
func (c *CreateConfig) CreateBlockIO() (*spec.LinuxBlockIO, error) {
	return c.createBlockIO()
}

func (c *CreateConfig) createExitCommand(runtime *libpod.Runtime) ([]string, error) {
	config, err := runtime.GetConfig()
	if err != nil {
		return nil, err
	}

	// We need a cleanup process for containers in the current model.
	// But we can't assume that the caller is Podman - it could be another
	// user of the API.
	// As such, provide a way to specify a path to Podman, so we can
	// still invoke a cleanup process.
	cmd := c.PodmanPath
	if cmd == "" {
		cmd, _ = os.Executable()
	}

	command := []string{cmd,
		"--root", config.StorageConfig.GraphRoot,
		"--runroot", config.StorageConfig.RunRoot,
		"--log-level", logrus.GetLevel().String(),
		"--cgroup-manager", config.CgroupManager,
		"--tmpdir", config.TmpDir,
	}
	if config.OCIRuntime != "" {
		command = append(command, []string{"--runtime", config.OCIRuntime}...)
	}
	if config.StorageConfig.GraphDriverName != "" {
		command = append(command, []string{"--storage-driver", config.StorageConfig.GraphDriverName}...)
	}
	for _, opt := range config.StorageConfig.GraphDriverOptions {
		command = append(command, []string{"--storage-opt", opt}...)
	}
	if config.EventsLogger != "" {
		command = append(command, []string{"--events-backend", config.EventsLogger}...)
	}

	if c.Syslog {
		command = append(command, "--syslog", "true")
	}
	command = append(command, []string{"container", "cleanup"}...)

	if c.Rm {
		command = append(command, "--rm")
	}

	return command, nil
}

// GetContainerCreateOptions takes a CreateConfig and returns a slice of CtrCreateOptions
func (c *CreateConfig) getContainerCreateOptions(runtime *libpod.Runtime, pod *libpod.Pod, mounts []spec.Mount, namedVolumes []*libpod.ContainerNamedVolume) ([]libpod.CtrCreateOption, error) {
	var options []libpod.CtrCreateOption
	var err error

	if c.Interactive {
		options = append(options, libpod.WithStdin())
	}
	if c.Systemd {
		options = append(options, libpod.WithSystemd())
	}
	if c.Name != "" {
		logrus.Debugf("setting container name %s", c.Name)
		options = append(options, libpod.WithName(c.Name))
	}
	if c.Pod != "" {
		logrus.Debugf("adding container to pod %s", c.Pod)
		options = append(options, runtime.WithPod(pod))
	}

	if len(mounts) != 0 || len(namedVolumes) != 0 {
		destinations := []string{}

		// Take all mount and named volume destinations.
		for _, mount := range mounts {
			destinations = append(destinations, mount.Destination)
		}
		for _, volume := range namedVolumes {
			destinations = append(destinations, volume.Dest)
		}

		options = append(options, libpod.WithUserVolumes(destinations))
	}

	if len(namedVolumes) != 0 {
		options = append(options, libpod.WithNamedVolumes(namedVolumes))
	}

	if len(c.UserCommand) != 0 {
		options = append(options, libpod.WithCommand(c.UserCommand))
	}

	// Add entrypoint unconditionally
	// If it's empty it's because it was explicitly set to "" or the image
	// does not have one
	options = append(options, libpod.WithEntrypoint(c.Entrypoint))

	// TODO: MNT, USER, CGROUP
	options = append(options, libpod.WithStopSignal(c.StopSignal))
	options = append(options, libpod.WithStopTimeout(c.StopTimeout))

	logPath := getLoggingPath(c.LogDriverOpt)
	if logPath != "" {
		options = append(options, libpod.WithLogPath(logPath))
	}

	if c.LogDriver != "" {
		options = append(options, libpod.WithLogDriver(c.LogDriver))
	}

	secOpts, err := c.Security.configureSecurity()
	// TODO FIXME wrapf
	if err != nil {
		return nil, err
	}
	options = append(options, secOpts...)

	useImageVolumes := c.ImageVolumeType == TypeBind
	// Gather up the options for NewContainer which consist of With... funcs
	options = append(options, libpod.WithRootFSFromImage(c.ImageID, c.Image, useImageVolumes))
	options = append(options, libpod.WithSecLabels(c.Security.LabelOpts))
	options = append(options, libpod.WithConmonPidFile(c.ConmonPidFile))
	options = append(options, libpod.WithLabels(c.Labels))
	// TODO FIXME maybe add this to namespaces?
	if c.Namespaces.IpcMode.IsHost() {
		options = append(options, libpod.WithShmDir("/dev/shm"))

	} else if c.Namespaces.IpcMode.IsContainer() {
		ctr, err := runtime.LookupContainer(c.Namespaces.IpcMode.Container())
		if err != nil {
			return nil, errors.Wrapf(err, "container %q not found", c.Namespaces.IpcMode.Container())
		}
		options = append(options, libpod.WithShmDir(ctr.ShmDir()))
	}
	options = append(options, libpod.WithShmSize(c.Resources.ShmSize))
	if c.Rootfs != "" {
		options = append(options, libpod.WithRootFS(c.Rootfs))
	}
	// Default used if not overridden on command line

	if c.RestartPolicy != "" {
		if c.RestartPolicy == "unless-stopped" {
			return nil, errors.Wrapf(define.ErrInvalidArg, "the unless-stopped restart policy is not supported")
		}

		split := strings.Split(c.RestartPolicy, ":")
		if len(split) > 1 {
			numTries, err := strconv.Atoi(split[1])
			if err != nil {
				return nil, errors.Wrapf(err, "%s is not a valid number of retries for restart policy", split[1])
			}
			if numTries < 0 {
				return nil, errors.Wrapf(define.ErrInvalidArg, "restart policy requires a positive number of retries")
			}
			options = append(options, libpod.WithRestartRetries(uint(numTries)))
		}
		options = append(options, libpod.WithRestartPolicy(split[0]))
	}

	// Always use a cleanup process to clean up Podman after termination
	exitCmd, err := c.createExitCommand(runtime)
	if err != nil {
		return nil, err
	}
	options = append(options, libpod.WithExitCommand(exitCmd))

	if c.HealthCheck != nil {
		options = append(options, libpod.WithHealthCheck(c.HealthCheck))
		logrus.Debugf("New container has a health check")
	}
	return options, nil
}

// AddPrivilegedDevices iterates through host devices and adds all
// host devices to the spec
func (c *CreateConfig) AddPrivilegedDevices(g *generate.Generator) error {
	return c.addPrivilegedDevices(g)
}
