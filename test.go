package main

import (
	"github.com/containers/libpod/libpod"
)

func main() {
	libpod.CheckConmonVersion("/usr/libexec/podman/conmon")
}
