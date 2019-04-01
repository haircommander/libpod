// +build linux

package libpod

import (
	"context"

	"github.com/containers/libpod/pkg/rootless"
	spec "github.com/opencontainers/runtime-spec/specs-go"
)

const (
	// IDTruncLength is the length of the pod's id that will be used to make the
	// infra container name
	IDTruncLength = 12
)

func (r *Runtime) InfraCommand() []string {
	return []string{r.config.InfraCommand}
}

// createInfraContainer wrap creates an infra container for a pod.
// An infra container becomes the basis for kernel namespace sharing between
// containers in the pod.
func (r *Runtime) createInfraContainer(ctx context.Context, p *Pod, infraSpec *spec.Spec, options []CtrCreateOption) (*Container, error) {
	if !r.valid {
		return nil, ErrRuntimeStopped
	}

	isRootless := rootless.IsRootless()

	//g.SetRootReadonly(true)
	// TODO can I remove this?
	//g.SetProcessArgs(entryCmd)

	//logrus.Debugf("Using %q as infra container entrypoint", entryCmd)

	//if isRootless {
	//	g.RemoveMount("/dev/pts")
	//	devPts := spec.Mount{
	//		Destination: "/dev/pts",
	//		Type:        "devpts",
	//		Source:      "devpts",
	//		Options:     []string{"private", "nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"},
	//	}
	//	g.AddMount(devPts)
	//}

	containerName := p.ID()[:IDTruncLength] + "-infra"
	options = append(options, r.WithPod(p))
	options = append(options, WithName(containerName))
	options = append(options, withIsInfra())

	// Since user namespace sharing is not implemented, we only need to check if it's rootless
	networks := make([]string, 0)
	netmode := "bridge"
	if isRootless {
		netmode = "slirp4netns"
	}
	options = append(options, WithNetNS(p.config.InfraContainer.PortBindings, isRootless, netmode, networks))

	return r.newContainer(ctx, infraSpec, options...)
}
