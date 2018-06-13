package integration

import (
	"os"
	"fmt"
    "strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Podman ps", func() {
	var (
		tempdir    string
		err        error
		podmanTest PodmanTest
	)

	BeforeEach(func() {
		tempdir, err = CreateTempDirInTempDir()
		if err != nil {
			os.Exit(1)
		}
		podmanTest = PodmanCreate(tempdir)
		podmanTest.RestoreAllArtifacts()
	})

	AfterEach(func() {
		podmanTest.Cleanup()

	})

	// It("podman ps no containers", func() {
	// 	session := podmanTest.Podman([]string{"ps"})
	// 	session.WaitWithDefaultTimeout()
	// 	Expect(session.ExitCode()).To(Equal(0))
	// })

	// It("podman ps default", func() {
	// 	session := podmanTest.RunTopContainer("")
	// 	session.WaitWithDefaultTimeout()
	// 	Expect(session.ExitCode()).To(Equal(0))

	// 	result := podmanTest.Podman([]string{"ps"})
	// 	result.WaitWithDefaultTimeout()
	// 	Expect(result.ExitCode()).To(Equal(0))
	// 	Expect(len(result.OutputToStringArray())).Should(BeNumerically(">", 0))
	// })

	// It("podman ps all", func() {
	// 	_, ec, _ := podmanTest.RunLsContainer("")
	// 	Expect(ec).To(Equal(0))

	// 	result := podmanTest.Podman([]string{"ps", "-a"})
	// 	result.WaitWithDefaultTimeout()
	// 	Expect(result.ExitCode()).To(Equal(0))
	// 	Expect(len(result.OutputToStringArray())).Should(BeNumerically(">", 0))
	// })

	// It("podman ps size flag", func() {
	// 	_, ec, _ := podmanTest.RunLsContainer("")
	// 	Expect(ec).To(Equal(0))

	// 	result := podmanTest.Podman([]string{"ps", "-a", "--size"})
	// 	result.WaitWithDefaultTimeout()
	// 	Expect(result.ExitCode()).To(Equal(0))
	// 	Expect(len(result.OutputToStringArray())).Should(BeNumerically(">", 0))
	// })

	// It("podman ps quiet flag", func() {
	// 	_, ec, fullCid := podmanTest.RunLsContainer("")
	// 	Expect(ec).To(Equal(0))

	// 	result := podmanTest.Podman([]string{"ps", "-a", "-q"})
	// 	result.WaitWithDefaultTimeout()
	// 	Expect(result.ExitCode()).To(Equal(0))
	// 	Expect(len(result.OutputToStringArray())).Should(BeNumerically(">", 0))
	// 	Expect(fullCid).To(ContainSubstring(result.OutputToStringArray()[0]))
	// })

	// It("podman ps latest flag", func() {
	// 	_, ec, _ := podmanTest.RunLsContainer("")
	// 	Expect(ec).To(Equal(0))

	// 	result := podmanTest.Podman([]string{"ps", "--latest"})
	// 	result.WaitWithDefaultTimeout()
	// 	Expect(result.ExitCode()).To(Equal(0))
	// 	Expect(len(result.OutputToStringArray())).Should(BeNumerically(">", 0))
	// })

	// It("podman ps last flag", func() {
	// 	_, ec, _ := podmanTest.RunLsContainer("test1")
	// 	Expect(ec).To(Equal(0))

	// 	_, ec, _ = podmanTest.RunLsContainer("test2")
	// 	Expect(ec).To(Equal(0))

	// 	_, ec, _ = podmanTest.RunLsContainer("test3")
	// 	Expect(ec).To(Equal(0))

	// 	result := podmanTest.Podman([]string{"ps", "--last", "2"})
	// 	result.WaitWithDefaultTimeout()
	// 	Expect(result.ExitCode()).To(Equal(0))
	// 	Expect(len(result.OutputToStringArray())).Should(Equal(3))
	// })

	// It("podman ps no-trunc", func() {
	// 	_, ec, fullCid := podmanTest.RunLsContainer("")
	// 	Expect(ec).To(Equal(0))

	// 	result := podmanTest.Podman([]string{"ps", "-aq", "--no-trunc"})
	// 	result.WaitWithDefaultTimeout()
	// 	Expect(result.ExitCode()).To(Equal(0))
	// 	Expect(len(result.OutputToStringArray())).Should(BeNumerically(">", 0))
	// 	Expect(fullCid).To(Equal(result.OutputToStringArray()[0]))
	// })

	// It("podman ps namespace flag", func() {
	// 	_, ec, _ := podmanTest.RunLsContainer("")
	// 	Expect(ec).To(Equal(0))

	// 	result := podmanTest.Podman([]string{"ps", "-a", "--namespace"})
	// 	result.WaitWithDefaultTimeout()
	// 	Expect(result.ExitCode()).To(Equal(0))
	// 	Expect(len(result.OutputToStringArray())).Should(BeNumerically(">", 0))
	// })

	// It("podman ps namespace flag with json format", func() {
	// 	_, ec, _ := podmanTest.RunLsContainer("test1")
	// 	Expect(ec).To(Equal(0))

	// 	result := podmanTest.Podman([]string{"ps", "-a", "--ns", "--format", "json"})
	// 	result.WaitWithDefaultTimeout()
	// 	Expect(result.ExitCode()).To(Equal(0))
	// 	Expect(result.IsJSONOutputValid()).To(BeTrue())
	// })

	// It("podman ps namespace flag with go template format", func() {
	// 	_, ec, _ := podmanTest.RunLsContainer("test1")
	// 	Expect(ec).To(Equal(0))

	// 	result := podmanTest.Podman([]string{"ps", "-a", "--format", "\"table {{.ID}} {{.Image}} {{.Labels}}\""})
	// 	result.WaitWithDefaultTimeout()
	// 	Expect(result.ExitCode()).To(Equal(0))
	// 	Expect(result.IsJSONOutputValid()).To(BeTrue())
	// })

	// It("podman ps ancestor filter flag", func() {
	// 	_, ec, _ := podmanTest.RunLsContainer("test1")
	// 	Expect(ec).To(Equal(0))

	// 	result := podmanTest.Podman([]string{"ps", "-a", "--filter", "ancestor=docker.io/library/alpine:latest"})
	// 	result.WaitWithDefaultTimeout()
	// 	Expect(result.ExitCode()).To(Equal(0))
	// })

	// It("podman ps id filter flag", func() {
	// 	_, ec, fullCid := podmanTest.RunLsContainer("")
	// 	Expect(ec).To(Equal(0))

	// 	result := podmanTest.Podman([]string{"ps", "-a", "--filter", fmt.Sprintf("id=%s", fullCid)})
	// 	result.WaitWithDefaultTimeout()
	// 	Expect(result.ExitCode()).To(Equal(0))
	// })

	// It("podman ps id filter flag", func() {
	// 	session := podmanTest.RunTopContainer("")
	// 	session.WaitWithDefaultTimeout()
	// 	Expect(session.ExitCode()).To(Equal(0))
	// 	fullCid := session.OutputToString()

	// 	result := podmanTest.Podman([]string{"ps", "-aq", "--no-trunc", "--filter", "status=running"})
	// 	result.WaitWithDefaultTimeout()
	// 	Expect(result.ExitCode()).To(Equal(0))
	// 	Expect(result.OutputToStringArray()[0]).To(Equal(fullCid))
	// })

	// It("podman ps mutually exclusive flags", func() {
	// 	session := podmanTest.Podman([]string{"ps", "-aqs"})
	// 	session.WaitWithDefaultTimeout()
	// 	Expect(session.ExitCode()).To(Not(Equal(0)))

	// 	session = podmanTest.Podman([]string{"ps", "-a", "--ns", "-s"})
	// 	session.WaitWithDefaultTimeout()
	// 	Expect(session.ExitCode()).To(Not(Equal(0)))
	// })

	It("podman --sort", func() {
		session := podmanTest.Podman([]string{"run", fedoraMinimal, "ls"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))
        fmt.Println(session.OutputToString())

		session = podmanTest.RunTopContainer("")
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))

		session = podmanTest.Podman([]string{"run", "busybox", "ls"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))

        session = podmanTest.Podman([]string{"run", "docker.io/kubernetes/pause", "ls"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))

		session = podmanTest.Podman([]string{"ps", "-a", "--sort=size", "--size"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))
        fmt.Println(strings.Join(session.OutputToStringArray(), "\n"))
		Expect(len(session.OutputToStringArray())).Should(BeNumerically(">", 0))
	})
})
