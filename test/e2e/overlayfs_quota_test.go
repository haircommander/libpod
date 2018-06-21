package integration

import (
	"os"
    "strings"
    "fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Podman overlayfs", func() {
	var (
		tempdir    string
		err        error
		podmanTest PodmanTest
        device     string
	)

	BeforeEach(func() {
        os.Setenv("STORAGE_OPTIONS", "--storage-opt overlay.size=180000 --storage-driver overlay")
		tempdir, err = CreateTempDirInTempDir()
		if err != nil {
			os.Exit(1)
		}
		podmanTest = PodmanCreate(tempdir)
		podmanTest.RestoreAllArtifacts()

        setup := podmanTest.SystemExec("dd", []string{"if=/dev/zero", "of=" + tempdir + "/virtfs", "bs=1024", "count=30720"})
        setup.WaitWithDefaultTimeout()
		Expect(setup.ExitCode()).To(Equal(0))

        setup = podmanTest.SystemExec("losetup", []string{"-f"})
        setup.WaitWithDefaultTimeout()
		Expect(setup.ExitCode()).To(Equal(0))
        device = strings.Replace(setup.OutputToString(), " ", "", -1)

        setup = podmanTest.SystemExec("losetup", []string{device, tempdir + "/virtfs"})
        setup.WaitWithDefaultTimeout()
		Expect(setup.ExitCode()).To(Equal(0))


        setup = podmanTest.SystemExec("mkfs.xfs", []string{device})
        setup.WaitWithDefaultTimeout()
		Expect(setup.ExitCode()).To(Equal(0))


        setup = podmanTest.SystemExec("mount", []string{"-t", "xfs", "-o", "prjquota", device, tempdir})
        setup.WaitWithDefaultTimeout()
		Expect(setup.ExitCode()).To(Equal(0))
        fmt.Println("I AM CALLED")
	})

	AfterEach(func() {
        cleanup := podmanTest.SystemExec("umount", []string{tempdir, "-l"})
        cleanup.WaitWithDefaultTimeout()
        Expect(cleanup.ExitCode()).To(Equal(0))

        cleanup = podmanTest.SystemExec("losetup", []string{"-d", device})
        cleanup.WaitWithDefaultTimeout()
        Expect(cleanup.ExitCode()).To(Equal(0))

        cleanup = podmanTest.Podman([]string{"rm", "-fa"})
        cleanup.Wait(90)

        cleanup = podmanTest.SystemExec("umount", []string{tempdir + "/crio/overlay"})
        cleanup.WaitWithDefaultTimeout()
        Expect(cleanup.ExitCode()).To(Equal(0))

        if err := os.RemoveAll(podmanTest.TempDir); err != nil {
            fmt.Printf("%q\n", err)
        }
        os.Setenv("STORAGE_OPTIONS", "")
	})
    // It("test", func() {
	// 	session := podmanTest.Podman([]string{"run", "--rm", ALPINE, "ls"})
	// 	session.WaitWithDefaultTimeout()
	// 	Expect(session.ExitCode()).To(Equal(0))
    //     Expect(session.ErrorToString()).To(BeEmpty())
    // })

    It("test", func() {
		session := podmanTest.Podman([]string{"run", "--rm", ALPINE, "ls"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Not(Equal(0)))
        grep, _ := session.ErrorGrepString("disk quota exceeded")
        Expect(grep).To(BeTrue())
    })
})
