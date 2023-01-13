//go:build !linux
// +build !linux

package configs

// Cgroup holds properties of a cgroup on Linux
// TODO Windows: This can ultimately be entirely factored out on Windows as
// cgroups are a Unix-specific construct.
type Cgroup struct{}

type FreezerState string

const (
	Undefined FreezerState = ""
	Frozen    FreezerState = "FROZEN"
	Thawed    FreezerState = "THAWED"
)
