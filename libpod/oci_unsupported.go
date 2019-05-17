// +build !linux

package libpod

import (
	"os"
)

func newPipe() (parent *os.File, child *os.File, err error) {
	return nil, nil, ErrNotImplemented
}

func (r *OCIRuntime) createContainer(ctr *Container, restoreOptions *ContainerCheckpointOptions) (err error) {
	return ErrNotImplemented
}

func (r *OCIRuntime) pathPackage() string {
	return ""
}

func (r *OCIRuntime) conmonPackage() string {
	return ""
}

func (r *OCIRuntime) createOCIContainer(ctr *Container, cgroupParent string, restoreOptions *ContainerCheckpointOptions) (err error) {
	return ErrOSNotSupported
}

func (r *OCIRuntime) execStopContainer(ctr *Container, timeout uint) error {
	return ErrOSNotSupported
}

func (r *OCIRuntime) stopContainer(ctr *Container, timeout uint) error {
	return ErrOSNotSupported
}

func readConmonPipeData(pipe *os.File) (int, error) {
	return -1, ErrOSNotSupported
}

func (r *OCIRuntime) execContainer(c *Container, cmd, capAdd, env []string, tty bool, cwd, user, sessionID string, streams *AttachStreams, preserveFDs int) (int, chan attachInfo, error) {
	return -1, nil, ErrOSNotSupported
}
