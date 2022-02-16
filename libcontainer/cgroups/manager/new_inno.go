//go:build inno
// +build inno

package manager

import (
	"errors"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/configs"
)
// New returns the instance of a cgroup manager, which is chosen
// based on the local environment (whether cgroup v1 or v2 is used)
// and the config (whether config.Systemd is set or not).
func New(config *configs.Cgroup) (cgroups.Manager, error) {
	return NewWithPaths(config, nil)
}

func NewWithPaths(config *configs.Cgroup, paths map[string]string) (cgroups.Manager, error) {
	return nil, errors.New("cgroups/manager.NewWithPaths: not supported")
}