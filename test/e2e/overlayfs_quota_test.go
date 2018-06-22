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
		podmanTest1 PodmanTest
        device     string
	)

	BeforeEach(func() {
		supertempdir, _ := CreateTempDirInTempDir()

		podmanTest1 = PodmanCreate(supertempdir)
		podmanTest1.RestoreAllArtifacts()

        os.Setenv("STORAGE_OPTIONS", "--storage-opt overlay.size=200000 --storage-driver overlay")
		tempdir, err = CreateTempDirInTempDir()
		if err != nil {
			os.Exit(1)
		}


        setup := podmanTest1.SystemExec("dd", []string{"if=/dev/zero", "of=" + supertempdir + "/virtfs", "bs=1024", "count=30720"})
        setup.WaitWithDefaultTimeout()
		Expect(setup.ExitCode()).To(Equal(0))

        setup = podmanTest1.SystemExec("losetup", []string{"-f"})
        setup.WaitWithDefaultTimeout()
		Expect(setup.ExitCode()).To(Equal(0))
        device = strings.Replace(setup.OutputToString(), " ", "", -1)

        setup = podmanTest1.SystemExec("losetup", []string{device, supertempdir + "/virtfs"})
        setup.WaitWithDefaultTimeout()
		Expect(setup.ExitCode()).To(Equal(0))


        setup = podmanTest1.SystemExec("mkfs.xfs", []string{device})
        setup.WaitWithDefaultTimeout()
		Expect(setup.ExitCode()).To(Equal(0))


        setup = podmanTest1.SystemExec("mount", []string{"-t", "xfs", "-o", "prjquota", device, tempdir})
        setup.WaitWithDefaultTimeout()
		Expect(setup.ExitCode()).To(Equal(0))

		podmanTest = PodmanCreate(tempdir)
		podmanTest.RestoreAllArtifacts()
	})

	AfterEach(func() {
        cleanup := podmanTest.Podman([]string{"rm", "-fa"})
        cleanup.Wait(90)


        cleanup = podmanTest.SystemExec("umount", []string{tempdir, "-l"})
        cleanup.WaitWithDefaultTimeout()
        Expect(cleanup.ExitCode()).To(Equal(0))

        cleanup = podmanTest.SystemExec("losetup", []string{"-d", device})
        cleanup.WaitWithDefaultTimeout()
        Expect(cleanup.ExitCode()).To(Equal(0))



        if err := os.RemoveAll(podmanTest.TempDir); err != nil {
            fmt.Printf("%q\n", err)
        }
        podmanTest1.Cleanup()
        os.Setenv("STORAGE_OPTIONS", "")
	})

    It("test", func() {
		session := podmanTest.Podman([]string{"--log-level=debug", "run", "--name", "test2", "-d", ALPINE, "ls"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))

		session = podmanTest.Podman([]string{"run", "--name", "test", "-d", ALPINE, "sleep", "5m"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))

        session = podmanTest.Podman([]string{"exec", "test", "/bin/bash", "-c", "'dd if=/dev/zero of=/tmp/file2.txt count=1024 bs=30720'"})
		Expect(session.ExitCode()).To(Not(Equal(0)))
        grep, _ := session.ErrorGrepString("disk quota exceeded")
        Expect(grep).To(BeTrue())
    })

})
