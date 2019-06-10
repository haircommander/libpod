// +build linux

package libpod

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/containerd/cgroups"
	"github.com/containers/libpod/pkg/lookup"
	"github.com/containers/libpod/pkg/util"
	"github.com/containers/libpod/utils"
	"github.com/coreos/go-systemd/activation"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/selinux/go-selinux"
	"github.com/opencontainers/selinux/go-selinux/label"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// newPipe creates a unix socket pair for communication
func newPipe() (parent *os.File, child *os.File, err error) {
	fds, err := unix.Socketpair(unix.AF_LOCAL, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(fds[1]), "parent"), os.NewFile(uintptr(fds[0]), "child"), nil
}

func (r *OCIRuntime) createOCIContainer(ctr *Container, restoreOptions *ContainerCheckpointOptions) (err error) {
	var stderrBuf bytes.Buffer

	runtimeDir, err := util.GetRootlessRuntimeDir()
	if err != nil {
		return err
	}

	parentSyncPipe, childSyncPipe, err := newPipe()
	if err != nil {
		return errors.Wrapf(err, "error creating socket pair")
	}
	defer parentSyncPipe.Close()

	childStartPipe, parentStartPipe, err := newPipe()
	if err != nil {
		return errors.Wrapf(err, "error creating socket pair for start pipe")
	}

	defer parentStartPipe.Close()

	args := r.sharedConmonArgs(ctr, ctr.ID(), ctr.bundlePath(), filepath.Join(ctr.state.RunDir, "pidfile"), ctr.LogPath(), r.exitsDir)

	if ctr.config.Spec.Process.Terminal {
		args = append(args, "-t")
	} else if ctr.config.Stdin {
		args = append(args, "-i")
	}

	if ctr.config.ConmonPidFile != "" {
		args = append(args, "--conmon-pidfile", ctr.config.ConmonPidFile)
	}

	if r.noPivot {
		args = append(args, "--no-pivot")
	}

	if len(ctr.config.ExitCommand) > 0 {
		args = append(args, "--exit-command", ctr.config.ExitCommand[0])
		for _, arg := range ctr.config.ExitCommand[1:] {
			args = append(args, []string{"--exit-command-arg", arg}...)
		}
	}

	if restoreOptions != nil {
		args = append(args, "--restore", ctr.CheckpointPath())
		if restoreOptions.TCPEstablished {
			args = append(args, "--runtime-opt", "--tcp-established")
		}
	}

	logrus.WithFields(logrus.Fields{
		"args": args,
	}).Debugf("running conmon: %s", r.conmonPath)

	cmd := exec.Command(r.conmonPath, args...)
	cmd.Dir = ctr.bundlePath()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	// TODO this is probably a really bad idea for some uses
	// Make this configurable
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if ctr.config.Spec.Process.Terminal {
		cmd.Stderr = &stderrBuf
	}

	// 0, 1 and 2 are stdin, stdout and stderr
	conmonEnv, envFiles := r.configureConmonEnv(runtimeDir)

	cmd.Env = append(r.conmonEnv, fmt.Sprintf("_OCI_SYNCPIPE=%d", 3), fmt.Sprintf("_OCI_STARTPIPE=%d", 4))
	cmd.Env = append(cmd.Env, conmonEnv...)
	cmd.ExtraFiles = append(cmd.ExtraFiles, childSyncPipe, childStartPipe)
	cmd.ExtraFiles = append(cmd.ExtraFiles, envFiles...)

	if r.reservePorts && !ctr.config.NetMode.IsSlirp4netns() {
		ports, err := bindPorts(ctr.config.PortMappings)
		if err != nil {
			return err
		}

		// Leak the port we bound in the conmon process.  These fd's won't be used
		// by the container and conmon will keep the ports busy so that another
		// process cannot use them.
		cmd.ExtraFiles = append(cmd.ExtraFiles, ports...)
	}

	if ctr.config.NetMode.IsSlirp4netns() {
		ctr.rootlessSlirpSyncR, ctr.rootlessSlirpSyncW, err = os.Pipe()
		if err != nil {
			return errors.Wrapf(err, "failed to create rootless network sync pipe")
		}
		// Leak one end in conmon, the other one will be leaked into slirp4netns
		cmd.ExtraFiles = append(cmd.ExtraFiles, ctr.rootlessSlirpSyncW)
	}

	err = startCommandGivenSelinux(cmd)
	// regardless of whether we errored or not, we no longer need the children pipes
	childSyncPipe.Close()
	childStartPipe.Close()
	if err != nil {
		return err
	}
	if err := r.moveConmonToCgroupAndSignal(ctr, cmd, parentStartPipe, ctr.ID()); err != nil {
		return err
	}
	/* Wait for initial setup and fork, and reap child */
	err = cmd.Wait()
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			if err2 := r.deleteContainer(ctr); err2 != nil {
				logrus.Errorf("Error removing container %s from runtime after creation failed", ctr.ID())
			}
		}
	}()
	pid, err := readConmonPipeData(parentSyncPipe)
	if err != nil {
		return err
	}
	ctr.state.PID = pid

	return nil
}

// prepareProcessExec returns the path of the process.json used in runc exec -p
// caller is responsible to close the returned *os.File if needed.
func prepareProcessExec(c *Container, cmd, env []string, tty bool, cwd, user, sessionID string) (*os.File, error) {
	f, err := ioutil.TempFile(c.execBundlePath(sessionID), "exec-process-")
	if err != nil {
		return nil, err
	}

	pspec := c.config.Spec.Process
	pspec.Args = cmd
	// We need to default this to false else it will inherit terminal as true
	// from the container.
	pspec.Terminal = false
	if tty {
		pspec.Terminal = true
	}
	if len(env) > 0 {
		pspec.Env = append(pspec.Env, env...)
	}

	if cwd != "" {
		pspec.Cwd = cwd

	}
	// If user was set, look it up in the container to get a UID to use on
	// the host
	if user != "" {
		execUser, err := lookup.GetUserGroupInfo(c.state.Mountpoint, user, nil)
		if err != nil {
			return nil, err
		}
		sgids := make([]uint32, 0, len(execUser.Sgids))
		for _, sgid := range execUser.Sgids {
			sgids = append(sgids, uint32(sgid))
		}
		processUser := spec.User{
			UID:            uint32(execUser.Uid),
			GID:            uint32(execUser.Gid),
			AdditionalGids: sgids,
		}

		pspec.User = processUser
	}

	processJSON, err := json.Marshal(pspec)
	if err != nil {
		return nil, err
	}

	if err := ioutil.WriteFile(f.Name(), processJSON, 0644); err != nil {
		return nil, err
	}
	return f, nil
}

// configureConmonEnv gets the environment values to add to conmon's exec struct
// TODO this may want to be less hardcoded/more configurable in the future
func (r *OCIRuntime) configureConmonEnv(runtimeDir string) ([]string, []*os.File) {
	env := make([]string, 0, 6)
	env = append(env, fmt.Sprintf("XDG_RUNTIME_DIR=%s", runtimeDir))
	env = append(env, fmt.Sprintf("_CONTAINERS_USERNS_CONFIGURED=%s", os.Getenv("_CONTAINERS_USERNS_CONFIGURED")))
	env = append(env, fmt.Sprintf("_CONTAINERS_ROOTLESS_UID=%s", os.Getenv("_CONTAINERS_ROOTLESS_UID")))
	env = append(env, fmt.Sprintf("HOME=%s", os.Getenv("HOME")))

	extraFiles := make([]*os.File, 0)
	if notify, ok := os.LookupEnv("NOTIFY_SOCKET"); ok {
		env = append(env, fmt.Sprintf("NOTIFY_SOCKET=%s", notify))
	}
	if listenfds, ok := os.LookupEnv("LISTEN_FDS"); ok {
		env = append(env, fmt.Sprintf("LISTEN_FDS=%s", listenfds), "LISTEN_PID=1")
		fds := activation.Files(false)
		extraFiles = append(extraFiles, fds...)
	}
	return env, extraFiles
}

func (r *OCIRuntime) sharedConmonArgs(ctr *Container, cuuid, bundlePath, pidPath, logPath, exitDir string) []string {
	args := []string{}
	if r.cgroupManager == SystemdCgroupsManager {
		args = append(args, "-s")
	}
	args = append(args, "-c", ctr.ID())
	args = append(args, "-u", cuuid)
	args = append(args, "-r", r.path)
	args = append(args, "-b", bundlePath)
	args = append(args, "-p", pidPath)

	logDriver := fmt.Sprintf("%s:%s", KubernetesLogging, logPath)
	if ctr.LogDriver() == JournaldLogging {
		logDriver = JournaldLogging
	}
	args = append(args, "-l", logDriver)
	args = append(args, "--exit-dir", exitDir)
	args = append(args, "--socket-dir-path", r.socketsDir)
	if r.logSizeMax >= 0 {
		args = append(args, "--log-size-max", fmt.Sprintf("%v", r.logSizeMax))
	}

	logLevel := logrus.GetLevel()
	args = append(args, "--log-level", logLevel.String())

	if logLevel == logrus.DebugLevel {
		logrus.Debugf("%s messages will be logged to syslog", r.conmonPath)
		args = append(args, "--syslog")
	}
	return args
}

func startCommandGivenSelinux(cmd *exec.Cmd) error {
	if !selinux.GetEnabled() {
		return cmd.Start()
	}
	// Set the label of the conmon process to be level :s0
	// This will allow the container processes to talk to fifo-files
	// passed into the container by conmon
	var (
		plabel string
		con    selinux.Context
		err    error
	)
	plabel, err = selinux.CurrentLabel()
	if err != nil {
		return errors.Wrapf(err, "Failed to get current SELinux label")
	}

	con, err = selinux.NewContext(plabel)
	if err != nil {
		return errors.Wrapf(err, "Failed to get new context from SELinux label")
	}

	runtime.LockOSThread()
	if con["level"] != "s0" && con["level"] != "" {
		con["level"] = "s0"
		if err = label.SetProcessLabel(con.Get()); err != nil {
			runtime.UnlockOSThread()
			return err
		}
	}
	err = cmd.Start()
	// Ignore error returned from SetProcessLabel("") call,
	// can't recover.
	label.SetProcessLabel("")
	runtime.UnlockOSThread()
	return err
}

func (r *OCIRuntime) moveConmonToCgroupAndSignal(ctr *Container, cmd *exec.Cmd, startFd *os.File, uuid string) error {
	cgroupParent := ctr.CgroupParent()
	if os.Geteuid() == 0 {
		if r.cgroupManager == SystemdCgroupsManager {
			unitName := createUnitName("libpod-conmon", uuid)

			realCgroupParent := cgroupParent
			splitParent := strings.Split(cgroupParent, "/")
			if strings.HasSuffix(cgroupParent, ".slice") && len(splitParent) > 1 {
				realCgroupParent = splitParent[len(splitParent)-1]
			}

			logrus.Infof("Running conmon under slice %s and unitName %s", realCgroupParent, unitName)
			if err := utils.RunUnderSystemdScope(cmd.Process.Pid, realCgroupParent, unitName); err != nil {
				logrus.Warnf("Failed to add conmon to systemd sandbox cgroup: %v", err)
			}
		} else {
			cgroupPath := filepath.Join(ctr.config.CgroupParent, "conmon")
			control, err := cgroups.New(cgroups.V1, cgroups.StaticPath(cgroupPath), &spec.LinuxResources{})
			if err != nil {
				logrus.Warnf("Failed to add conmon to cgroupfs sandbox cgroup: %v", err)
			} else {
				// we need to remove this defer and delete the cgroup once conmon exits
				// maybe need a conmon monitor?
				if err := control.Add(cgroups.Process{Pid: cmd.Process.Pid}); err != nil {
					logrus.Warnf("Failed to add conmon to cgroupfs sandbox cgroup: %v", err)
				}
			}
		}
	}
	/* We set the cgroup, now the child can start creating children */
	if err := sendDataDownPipe(startFd); err != nil {
		return err
	}
	return nil
}

func formatRuntimeOpts(opts ...string) []string {
	args := make([]string, 0, len(opts)*2)
	for _, o := range opts {
		args = append(args, "--runtime-opt", o)
	}
	return args
}
