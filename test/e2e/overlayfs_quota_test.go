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
        os.Setenv("STORAGE_OPTIONS", "--storage-opt overlay.size=1.004608M --storage-driver overlay")
		tempdir, err = CreateTempDirInTempDir()
		if err != nil {
			os.Exit(1)
		}

		podmanTest = PodmanCreate(tempdir)

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

		podmanTest.RestoreAllArtifactsXFS()
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
        os.Setenv("STORAGE_OPTIONS", "")
	})

    It("test", func() {
        session := podmanTest.Podman([]string{"run", "--security-opt", "label=disable", ALPINE,  "sh", "-c", "dd if=/dev/zero of=file.txt count=1048576 bs=1"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))
    })


    It("test2", func() {
        session := podmanTest.Podman([]string{"run",  "--security-opt",  "label=disable", ALPINE,  "sh", "-c", "dd if=/dev/zero of=file.txt count=1048577 bs=1"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Not(Equal(0)))
        grep, _ := session.ErrorGrepString("No space left on device")
		Expect(grep).To(BeTrue())
    })

    It("test3", func() {
        session := podmanTest.Podman([]string{"run", "--security-opt", "label=disable", "busybox",  "sh", "-c", "dd if=/dev/zero of=file.txt count=1048576 bs=1"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Equal(0))
    })


    It("test4", func() {
        session := podmanTest.Podman([]string{"run",  "--security-opt",  "label=disable", "busybox",  "sh", "-c", "dd if=/dev/zero of=file.txt count=1048577 bs=1"})
		session.WaitWithDefaultTimeout()
		Expect(session.ExitCode()).To(Not(Equal(0)))
        grep, _ := session.ErrorGrepString("No space left on device")
		Expect(grep).To(BeTrue())
    })
})
