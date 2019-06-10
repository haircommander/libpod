// +build linux

package libpod

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/containers/libpod/pkg/rootless"
	"github.com/containers/libpod/pkg/util"
	"github.com/containers/libpod/utils"
	pmount "github.com/containers/storage/pkg/mount"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"k8s.io/client-go/tools/remotecommand"
)

const unknownPackage = "Unknown"

func sendDataDownPipe(pipe *os.File) error {
	someData := []byte{0}
	_, err := pipe.Write(someData)
	return err
}

// makeAccessible changes the path permission and each parent directory to have --x--x--x
func makeAccessible(path string, uid, gid int) error {
	for ; path != "/"; path = filepath.Dir(path) {
		st, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if int(st.Sys().(*syscall.Stat_t).Uid) == uid && int(st.Sys().(*syscall.Stat_t).Gid) == gid {
			continue
		}
		if st.Mode()&0111 != 0111 {
			if err := os.Chmod(path, os.FileMode(st.Mode()|0111)); err != nil {
				return err
			}
		}
	}
	return nil
}

// CreateContainer creates a container in the OCI runtime
// TODO terminal support for container
// Presently just ignoring conmon opts related to it
func (r *OCIRuntime) createContainer(ctr *Container, restoreOptions *ContainerCheckpointOptions) (err error) {
	if len(ctr.config.IDMappings.UIDMap) != 0 || len(ctr.config.IDMappings.GIDMap) != 0 {
		for _, i := range []string{ctr.state.RunDir, ctr.runtime.config.TmpDir, ctr.config.StaticDir, ctr.state.Mountpoint, ctr.runtime.config.VolumePath} {
			if err := makeAccessible(i, ctr.RootUID(), ctr.RootGID()); err != nil {
				return err
			}
		}

		// if we are running a non privileged container, be sure to umount some kernel paths so they are not
		// bind mounted inside the container at all.
		if !ctr.config.Privileged && !rootless.IsRootless() {
			ch := make(chan error)
			go func() {
				runtime.LockOSThread()
				err := func() error {
					fd, err := os.Open(fmt.Sprintf("/proc/%d/task/%d/ns/mnt", os.Getpid(), unix.Gettid()))
					if err != nil {
						return err
					}
					defer fd.Close()

					// create a new mountns on the current thread
					if err = unix.Unshare(unix.CLONE_NEWNS); err != nil {
						return err
					}
					defer unix.Setns(int(fd.Fd()), unix.CLONE_NEWNS)

					// don't spread our mounts around.  We are setting only /sys to be slave
					// so that the cleanup process is still able to umount the storage and the
					// changes are propagated to the host.
					err = unix.Mount("/sys", "/sys", "none", unix.MS_REC|unix.MS_SLAVE, "")
					if err != nil {
						return errors.Wrapf(err, "cannot make /sys slave")
					}

					mounts, err := pmount.GetMounts()
					if err != nil {
						return err
					}
					for _, m := range mounts {
						if !strings.HasPrefix(m.Mountpoint, "/sys/kernel") {
							continue
						}
						err = unix.Unmount(m.Mountpoint, 0)
						if err != nil && !os.IsNotExist(err) {
							return errors.Wrapf(err, "cannot unmount %s", m.Mountpoint)
						}
					}
					return r.createOCIContainer(ctr, restoreOptions)
				}()
				ch <- err
			}()
			err := <-ch
			return err
		}
	}
	return r.createOCIContainer(ctr, restoreOptions)
}

func rpmVersion(path string) string {
	output := unknownPackage
	cmd := exec.Command("/usr/bin/rpm", "-q", "-f", path)
	if outp, err := cmd.Output(); err == nil {
		output = string(outp)
	}
	return strings.Trim(output, "\n")
}

func dpkgVersion(path string) string {
	output := unknownPackage
	cmd := exec.Command("/usr/bin/dpkg", "-S", path)
	if outp, err := cmd.Output(); err == nil {
		output = string(outp)
	}
	return strings.Trim(output, "\n")
}

func (r *OCIRuntime) pathPackage() string {
	if out := rpmVersion(r.path); out != unknownPackage {
		return out
	}
	return dpkgVersion(r.path)
}

func (r *OCIRuntime) conmonPackage() string {
	if out := rpmVersion(r.conmonPath); out != unknownPackage {
		return out
	}
	return dpkgVersion(r.conmonPath)
}

func readConmonPipeData(pipe *os.File) (int, error) {
	// Wait to get container pid from conmon
	type syncStruct struct {
		si  *syncInfo
		err error
	}
	ch := make(chan syncStruct)
	go func() {
		var si *syncInfo
		rdr := bufio.NewReader(pipe)
		b, err := rdr.ReadBytes('\n')
		if err != nil {
			ch <- syncStruct{err: err}
		}
		if err := json.Unmarshal(b, &si); err != nil {
			ch <- syncStruct{err: err}
			return
		}
		ch <- syncStruct{si: si}
	}()

	data := -1
	select {
	case ss := <-ch:
		if ss.err != nil {
			return -1, errors.Wrapf(ss.err, "error reading container (probably exited) json message")
		}
		logrus.Debugf("Received: %d", ss.si.Data)
		if ss.si.Data < 0 {
			if ss.si.Message != "" {
				return ss.si.Data, errors.Wrapf(ErrInternal, "container create failed: %s", ss.si.Message)
			}
			return ss.si.Data, errors.Wrapf(ErrInternal, "container create failed")
		}
		data = ss.si.Data
	case <-time.After(ContainerCreateTimeout):
		return -1, errors.Wrapf(ErrInternal, "container creation timeout")
	}
	return data, nil
}

// execContainer executes a command in a running container
// TODO: Add --detach support
// TODO: Convert to use conmon
// TODO: add --pid-file and use that to generate exec session tracking
func (r *OCIRuntime) execContainer(c *Container, cmd, capAdd, env []string, tty bool, cwd, user, sessionID string, streams *AttachStreams, preserveFDs int, resize chan remotecommand.TerminalSize, detachKeys string) (int, chan attachInfo, error) {
	if len(cmd) == 0 {
		return -1, nil, errors.Wrapf(ErrInvalidArg, "must provide a command to execute")
	}

	if sessionID == "" {
		return -1, nil, errors.Wrapf(ErrEmptyID, "must provide a session ID for exec")
	}

	// create sync pipe to receive the pid
	parentSyncPipe, childSyncPipe, err := newPipe()
	if err != nil {
		return -1, nil, errors.Wrapf(err, "error creating socket pair")
	}

	// create start pipe to set the cgroup before running
	childStartPipe, parentStartPipe, err := newPipe()
	if err != nil {
		return -1, nil, errors.Wrapf(err, "error creating socket pair")
	}
	defer parentStartPipe.Close()

	// create the attach pipe to allow attach socket to be created before
	// $RUNTIME exec starts running. This is to make sure we can capture all output
	// from the process through that socket, rather than half reading the log, half attaching to the socket
	parentAttachPipe, childAttachPipe, err := newPipe()
	if err != nil {
		return -1, nil, errors.Wrapf(err, "error creating socket pair")
	}
	//defer parentAttachPipe.Close()

	childrenClosed := false
	defer func() {
		if !childrenClosed {
			childSyncPipe.Close()
			childAttachPipe.Close()
			childStartPipe.Close()
		}
	}()

	runtimeDir, err := util.GetRootlessRuntimeDir()
	if err != nil {
		return -1, nil, err
	}

	processFile, err := prepareProcessExec(c, cmd, env, tty, cwd, user, sessionID)
	if err != nil {
		return -1, nil, err
	}

	args := r.sharedConmonArgs(c, sessionID, c.execBundlePath(sessionID), c.execPidPath(sessionID), c.execLogPath(sessionID), c.execExitFilePath(sessionID))

	if preserveFDs > 0 {
		args = append(args, formatRuntimeOpts("--preserve-fds", string(preserveFDs))...)
	}

	for _, capability := range capAdd {
		args = append(args, formatRuntimeOpts("--cap", capability)...)
	}

	if tty {
		args = append(args, "-t")
	}
	//if streams.AttachInput {
	//	args = append(args, "-i")
	//}

	// Append container ID and command
	args = append(args, "-e")
	// TODO FIXME option
	args = append(args, "--attach")
	args = append(args, "--exec-process-spec", processFile.Name())

	logrus.WithFields(logrus.Fields{
		"args": args,
	}).Debugf("running conmon: %s", r.conmonPath)

	execCmd := exec.Command(r.conmonPath, args...)

	if streams.AttachInput {
		execCmd.Stdin = streams.InputStream
	}
	if streams.AttachOutput {
		execCmd.Stdout = streams.OutputStream
	}
	if streams.AttachError {
		execCmd.Stderr = streams.ErrorStream
	}

	conmonEnv, extraFiles := r.configureConmonEnv(runtimeDir)

	// we don't want to step on users fds they asked to preserve
	// Since 0-2 are used for stdio, start the fds we pass in at preserveFDs+3
	execCmd.Env = append(r.conmonEnv, fmt.Sprintf("_OCI_SYNCPIPE=%d", preserveFDs+3), fmt.Sprintf("_OCI_STARTPIPE=%d", preserveFDs+4), fmt.Sprintf("_OCI_ATTACHPIPE=%d", preserveFDs+5))
	execCmd.Env = append(execCmd.Env, conmonEnv...)

	execCmd.ExtraFiles = append(execCmd.ExtraFiles, childSyncPipe, childStartPipe, childAttachPipe)
	execCmd.ExtraFiles = append(execCmd.ExtraFiles, extraFiles...)
	execCmd.Dir = c.execBundlePath(sessionID)
	execCmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	if preserveFDs > 0 {
		for fd := 3; fd < 3+preserveFDs; fd++ {
			execCmd.ExtraFiles = append(execCmd.ExtraFiles, os.NewFile(uintptr(fd), fmt.Sprintf("fd-%d", fd)))
		}
	}

	err = startCommandGivenSelinux(execCmd)
	// we don't need the fds of the children
	childSyncPipe.Close()
	childStartPipe.Close()
	childAttachPipe.Close()
	childrenClosed = true
	if err != nil {
		return -1, nil, errors.Wrapf(err, "cannot start container %s", c.ID())
	}
	if err := r.moveConmonToCgroupAndSignal(c, execCmd, parentStartPipe, sessionID); err != nil {
		return -1, nil, err
	}

	if preserveFDs > 0 {
		for fd := 3; fd < 3+preserveFDs; fd++ {
			// These fds were passed down to the runtime.  Close them
			// and not interfere
			os.NewFile(uintptr(fd), fmt.Sprintf("fd-%d", fd)).Close()
		}
	}

	// TODO FIXME if !detach
	// Attach to the container before starting it
	attachChan := make(chan attachInfo)
	go func() {
		ec, err := c.attachToExec(streams, detachKeys, resize, sessionID, parentStartPipe, parentAttachPipe)
		attachChan <- attachInfo{ExitCode: ec, Error: err}
	}()

	syncChan := make(chan attachInfo)

	defer close(syncChan)

	go func() {
		defer parentSyncPipe.Close()
		pid, err := readConmonPipeData(parentSyncPipe)
		syncChan <- attachInfo{ExitCode: pid, Error: err}
	}()

	syncInfo := <-syncChan
	return syncInfo.ExitCode, attachChan, syncInfo.Error
}

// Wait for a container which has been sent a signal to stop
func waitContainerStop(ctr *Container, timeout time.Duration) error {
	done := make(chan struct{})
	chControl := make(chan struct{})
	go func() {
		for {
			select {
			case <-chControl:
				return
			default:
				// Check if the process is still around
				err := unix.Kill(ctr.state.PID, 0)
				if err == unix.ESRCH {
					close(done)
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()
	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		close(chControl)
		logrus.Debugf("container %s did not die within timeout %d", ctr.ID(), timeout)
		return errors.Errorf("container %s did not die within timeout", ctr.ID())
	}
}

// Wait for a set of given PIDs to stop
func waitPidsStop(pids []int, timeout time.Duration) error {
	done := make(chan struct{})
	chControl := make(chan struct{})
	go func() {
		for {
			select {
			case <-chControl:
				return
			default:
				allClosed := true
				for _, pid := range pids {
					if err := unix.Kill(pid, 0); err != unix.ESRCH {
						allClosed = false
						break
					}
				}
				if allClosed {
					close(done)
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()
	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		close(chControl)
		return errors.Errorf("given PIDs did not die within timeout")
	}
}

// stopContainer stops a container, first using its given stop signal (or
// SIGTERM if no signal was specified), then using SIGKILL
// Timeout is given in seconds. If timeout is 0, the container will be
// immediately kill with SIGKILL
// Does not set finished time for container, assumes you will run updateStatus
// after to pull the exit code
func (r *OCIRuntime) stopContainer(ctr *Container, timeout uint) error {
	logrus.Debugf("Stopping container %s (PID %d)", ctr.ID(), ctr.state.PID)

	// Ping the container to see if it's alive
	// If it's not, it's already stopped, return
	err := unix.Kill(ctr.state.PID, 0)
	if err == unix.ESRCH {
		return nil
	}

	stopSignal := ctr.config.StopSignal
	if stopSignal == 0 {
		stopSignal = uint(syscall.SIGTERM)
	}

	if timeout > 0 {
		if err := r.killContainer(ctr, stopSignal); err != nil {
			// Is the container gone?
			// If so, it probably died between the first check and
			// our sending the signal
			// The container is stopped, so exit cleanly
			err := unix.Kill(ctr.state.PID, 0)
			if err == unix.ESRCH {
				return nil
			}

			return err
		}

		if err := waitContainerStop(ctr, time.Duration(timeout)*time.Second); err != nil {
			logrus.Warnf("Timed out stopping container %s, resorting to SIGKILL", ctr.ID())
		} else {
			// No error, the container is dead
			return nil
		}
	}

	var args []string
	if rootless.IsRootless() {
		// we don't use --all for rootless containers as the OCI runtime might use
		// the cgroups to determine the PIDs, but for rootless containers there is
		// not any.
		args = []string{"kill", ctr.ID(), "KILL"}
	} else {
		args = []string{"kill", "--all", ctr.ID(), "KILL"}
	}

	runtimeDir, err := util.GetRootlessRuntimeDir()
	if err != nil {
		return err
	}
	env := []string{fmt.Sprintf("XDG_RUNTIME_DIR=%s", runtimeDir)}
	if err := utils.ExecCmdWithStdStreams(os.Stdin, os.Stdout, os.Stderr, env, r.path, args...); err != nil {
		// Again, check if the container is gone. If it is, exit cleanly.
		err := unix.Kill(ctr.state.PID, 0)
		if err == unix.ESRCH {
			return nil
		}

		return errors.Wrapf(err, "error sending SIGKILL to container %s", ctr.ID())
	}

	// Give runtime a few seconds to make it happen
	if err := waitContainerStop(ctr, killContainerTimeout); err != nil {
		return err
	}

	return nil
}

// execStopContainer stops all active exec sessions in a container
// It will also stop all other processes in the container. It is only intended
// to be used to assist in cleanup when removing a container.
// SIGTERM is used by default to stop processes. If SIGTERM fails, SIGKILL will be used.
func (r *OCIRuntime) execStopContainer(ctr *Container, timeout uint) error {
	// Do we have active exec sessions?
	if len(ctr.state.ExecSessions) == 0 {
		return nil
	}

	// Get a list of active exec sessions
	execSessions := []int{}
	for _, session := range ctr.state.ExecSessions {
		pid := session.PID
		// Ping the PID with signal 0 to see if it still exists
		if err := unix.Kill(pid, 0); err == unix.ESRCH {
			continue
		}

		execSessions = append(execSessions, pid)
	}

	// All the sessions may be dead
	// If they are, just return
	if len(execSessions) == 0 {
		return nil
	}
	runtimeDir, err := util.GetRootlessRuntimeDir()
	if err != nil {
		return err
	}
	env := []string{fmt.Sprintf("XDG_RUNTIME_DIR=%s", runtimeDir)}

	// If timeout is 0, just use SIGKILL
	if timeout > 0 {
		// Stop using SIGTERM by default
		// Use SIGSTOP after a timeout
		logrus.Debugf("Killing all processes in container %s with SIGTERM", ctr.ID())
		if err := utils.ExecCmdWithStdStreams(os.Stdin, os.Stdout, os.Stderr, env, r.path, "kill", "--all", ctr.ID(), "TERM"); err != nil {
			return errors.Wrapf(err, "error sending SIGTERM to container %s processes", ctr.ID())
		}

		// Wait for all processes to stop
		if err := waitPidsStop(execSessions, time.Duration(timeout)*time.Second); err != nil {
			logrus.Warnf("Timed out stopping container %s exec sessions", ctr.ID())
		} else {
			// No error, all exec sessions are dead
			return nil
		}
	}

	// Send SIGKILL
	logrus.Debugf("Killing all processes in container %s with SIGKILL", ctr.ID())
	if err := utils.ExecCmdWithStdStreams(os.Stdin, os.Stdout, os.Stderr, env, r.path, "kill", "--all", ctr.ID(), "KILL"); err != nil {
		return errors.Wrapf(err, "error sending SIGKILL to container %s processes", ctr.ID())
	}

	// Give the processes a few seconds to go down
	if err := waitPidsStop(execSessions, killContainerTimeout); err != nil {
		return errors.Wrapf(err, "failed to kill container %s exec sessions", ctr.ID())
	}

	return nil
}
