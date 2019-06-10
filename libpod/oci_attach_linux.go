//+build linux

package libpod

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/containers/libpod/pkg/kubeutils"
	"github.com/containers/libpod/utils"
	"github.com/docker/docker/pkg/term"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"k8s.io/client-go/tools/remotecommand"
)

//#include <sys/un.h>
// extern int unix_path_length(){struct sockaddr_un addr; return sizeof(addr.sun_path) - 1;}
import "C"

/* Sync with stdpipe_t in conmon.c */
const (
	AttachPipeStdin  = 1
	AttachPipeStdout = 2
	AttachPipeStderr = 3
)

// Attach to the given container
// Does not check if state is appropriate
func (c *Container) attach(streams *AttachStreams, keys string, resize <-chan remotecommand.TerminalSize, startContainer bool, wg *sync.WaitGroup) error {
	if !streams.AttachOutput && !streams.AttachError && !streams.AttachInput {
		return errors.Wrapf(ErrInvalidArg, "must provide at least one stream to attach to")
	}

	detachKeys, err := processDetachKeys(keys)
	if err != nil {
		return err
	}

	logrus.Debugf("Attaching to container %s", c.ID())

	registerResizeFunc(resize, c.bundlePath())

	socketPath := buildSocketPath(c.AttachSocketPath())

	conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: socketPath, Net: "unixpacket"})
	if err != nil {
		return errors.Wrapf(err, "failed to connect to container's attach socket: %v", socketPath)
	}
	defer conn.Close()

	// If starting was requested, start the container and notify when that's
	// done.
	if startContainer {
		if err := c.start(); err != nil {
			return err
		}
		wg.Done()
	}

	receiveStdoutError, stdinDone := setupStdioChannels(streams, conn, detachKeys)

	select {
	case err := <-receiveStdoutError:
		return err
	case err := <-stdinDone:
		if err == ErrDetach {
			return err
		}
		if streams.AttachOutput || streams.AttachError {
			return <-receiveStdoutError
		}
	}

	return nil
}

// Attach to the given container's exec session
// attachFd and startFd must be open file descriptors
// attachFd must be the output side of the fd. attachFd is used for two things:
//  conmon will first send a nonse value across the pipe indicating it has set up its side of the console socket
//    this ensures attachToExec gets all of the output of the called process
//  conmon will then send the exit code of the exec process, or an error in the exec session
// startFd must be the input side of the fd.
//   conmon will wait to start the exec session until the parent process has setup the console socket.
//   Once attachToExec successfully attaches to the console socket, the child conmon process responsible for calling runtime exec
//     will read from the output side of start fd, thus learning to start the child process.
// Thus, the order goes as follow:
// 1. conmon parent process sets up its console socket. sends on attachFd
// 2. attachToExec attaches to the console socket after reading on attachFd
// 3. child waits on startFd for attachToExec to attach to said console socket
// 4. attachToExec sends on startFd, signalling it has attached to the socket and child is ready to go
// 5. child receives on startFd, runs the runtime exec command
// 6. Eventually, parent sends (along attachFd) the exit code to attachToExec, signalling the end of the process
func (c *Container) attachToExec(streams *AttachStreams, keys string, resize <-chan remotecommand.TerminalSize, sessionID string, startFd *os.File, attachFd *os.File) (int, error) {
	if !streams.AttachOutput && !streams.AttachError && !streams.AttachInput {
		return -1, errors.Wrapf(ErrInvalidArg, "must provide at least one stream to attach to")
	}
	if startFd == nil || attachFd == nil {
		return -1, errors.Wrapf(ErrInvalidArg, "start sync pipe and attach sync pipe must be defined for exec attach")
	}

	detachKeys, err := processDetachKeys(keys)
	if err != nil {
		return -1, err
	}

	logrus.Debugf("Attaching to container %s exec session %s", c.ID(), sessionID)

	registerResizeFunc(resize, c.execBundlePath(sessionID))

	// set up the socket path, such that it is the correct length and location for exec
	socketPath := buildSocketPath(c.execAttachSocketPath(sessionID))

	// 2: read from attachFd that the parent process has set up the console socket
	if _, err := readConmonPipeData(attachFd); err != nil {
		return -1, err
	}
	// 2: then attach
	conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: socketPath, Net: "unixpacket"})
	if err != nil {
		return -1, errors.Wrapf(err, "failed to connect to container's attach socket: %v", socketPath)
	}
	defer conn.Close()

	// start listening on stdio of the process
	receiveStdoutError, stdinDone := setupStdioChannels(streams, conn, detachKeys)

	// 4: send start message to child
	if err := sendDataDownPipe(startFd); err != nil {
		return -1, err
	}

	select {
	case err = <-receiveStdoutError:
		break
	case err = <-stdinDone:
		if err == ErrDetach {
			break
		}
		if streams.AttachOutput || streams.AttachError {
			err = <-receiveStdoutError
		}
	}
	exitCode, err2 := c.readExitCode(sessionID)
	if err2 != nil {
		logrus.Debugf("reading exec exit file returned error %s", err2.Error())
		if err == nil {
			err = err2
		}
	}
	return exitCode, err
}

func (c *Container) readExitCode(sessionID string) (int, error) {
	exitFileName := c.execExitFilePath(sessionID)
	ec, err := ioutil.ReadFile(filepath.Join(exitFileName, c.ID()))
	if err != nil {
		return -1, err
	}
	ecInt, err := strconv.Atoi(string(ec))
	if err != nil {
		return -1, err
	}
	return ecInt, nil
}

func processDetachKeys(keys string) ([]byte, error) {
	// Check the validity of the provided keys first
	var err error
	detachKeys := []byte{}
	if len(keys) > 0 {
		detachKeys, err = term.ToBytes(keys)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid detach keys")
		}
	}
	return detachKeys, nil
}

func registerResizeFunc(resize <-chan remotecommand.TerminalSize, bundlePath string) {
	kubeutils.HandleResizing(resize, func(size remotecommand.TerminalSize) {
		controlPath := filepath.Join(bundlePath, "ctl")
		controlFile, err := os.OpenFile(controlPath, unix.O_WRONLY, 0)
		if err != nil {
			logrus.Debugf("Could not open ctl file: %v", err)
			return
		}
		defer controlFile.Close()

		logrus.Debugf("Received a resize event: %+v", size)
		if _, err = fmt.Fprintf(controlFile, "%d %d %d\n", 1, size.Height, size.Width); err != nil {
			logrus.Warnf("Failed to write to control file to resize terminal: %v", err)
		}
	})
}

func buildSocketPath(socketPath string) string {
	maxUnixLength := int(C.unix_path_length())
	if maxUnixLength < len(socketPath) {
		socketPath = socketPath[0:maxUnixLength]
	}

	logrus.Debug("connecting to socket ", socketPath)
	return socketPath
}

func setupStdioChannels(streams *AttachStreams, conn *net.UnixConn, detachKeys []byte) (chan error, chan error) {
	receiveStdoutError := make(chan error)
	go func() {
		receiveStdoutError <- redirectResponseToOutputStreams(streams.OutputStream, streams.ErrorStream, streams.AttachOutput, streams.AttachError, conn)
	}()

	stdinDone := make(chan error)
	go func() {
		var err error
		if streams.AttachInput {
			_, err = utils.CopyDetachable(conn, streams.InputStream, detachKeys)
			conn.CloseWrite()
		}
		stdinDone <- err
	}()

	return receiveStdoutError, stdinDone
}

func redirectResponseToOutputStreams(outputStream, errorStream io.Writer, writeOutput, writeError bool, conn io.Reader) error {
	var err error
	buf := make([]byte, 8192+1) /* Sync with conmon STDIO_BUF_SIZE */
	for {
		nr, er := conn.Read(buf)
		if nr > 0 {
			var dst io.Writer
			var doWrite bool
			switch buf[0] {
			case AttachPipeStdout:
				dst = outputStream
				doWrite = writeOutput
			case AttachPipeStderr:
				dst = errorStream
				doWrite = writeError
			default:
				logrus.Infof("Received unexpected attach type %+d", buf[0])
			}

			if doWrite {
				nw, ew := dst.Write(buf[1:nr])
				if ew != nil {
					err = ew
					break
				}
				if nr != nw+1 {
					err = io.ErrShortWrite
					break
				}
			}
		}
		if er == io.EOF {
			break
		}
		if er != nil {
			err = er
			break
		}
	}
	return err
}
