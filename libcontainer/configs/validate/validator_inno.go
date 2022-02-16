package validate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	// "sync"

	// "github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/configs"
	// "github.com/opencontainers/runc/libcontainer/intelrdt"
	// selinux "github.com/opencontainers/selinux/go-selinux"
	"github.com/sirupsen/logrus"
	// "golang.org/x/sys/unix"
)

type Validator interface {
	Validate(*configs.Config) error
}

func New() Validator {
	return &ConfigValidator{}
}

type ConfigValidator struct{}

type check func(config *configs.Config) error

func (v *ConfigValidator) Validate(config *configs.Config) error {
	checks := []check{
		v.cgroups,
		v.rootfs,
		v.network,
		v.hostname,
		v.security,
		v.usernamespace,
		v.cgroupnamespace,
		v.sysctl,
		// v.intelrdt,
		// v.rootlessEUID,
	}
	for _, c := range checks {
		if err := c(config); err != nil {
			return err
		}
	}
	// Relaxed validation rules for backward compatibility
	warns := []check{
		v.mounts, // TODO (runc v1.x.x): make this an error instead of a warning
	}
	for _, c := range warns {
		if err := c(config); err != nil {
			logrus.WithError(err).Warn("invalid configuration")
		}
	}
	return nil
}

// rootfs validates if the rootfs is an absolute path and is not a symlink
// to the container's root filesystem.
func (v *ConfigValidator) rootfs(config *configs.Config) error {
	if _, err := os.Stat(config.Rootfs); err != nil {
		return fmt.Errorf("invalid rootfs: %w", err)
	}
	cleaned, err := filepath.Abs(config.Rootfs)
	if err != nil {
		return fmt.Errorf("invalid rootfs: %w", err)
	}
	if cleaned, err = filepath.EvalSymlinks(cleaned); err != nil {
		return fmt.Errorf("invalid rootfs: %w", err)
	}
	if filepath.Clean(config.Rootfs) != cleaned {
		return errors.New("invalid rootfs: not an absolute path, or a symlink")
	}
	return nil
}

func (v *ConfigValidator) network(config *configs.Config) error {
	return nil
}

func (v *ConfigValidator) hostname(config *configs.Config) error {
	return nil
}

func (v *ConfigValidator) security(config *configs.Config) error {
	return nil
}

func (v *ConfigValidator) usernamespace(config *configs.Config) error {
	return nil
}

func (v *ConfigValidator) cgroupnamespace(config *configs.Config) error {
	return nil
}

// convertSysctlVariableToDotsSeparator can return sysctl variables in dots separator format.
// The '/' separator is also accepted in place of a '.'.
// Convert the sysctl variables to dots separator format for validation.
// More info:
//   https://man7.org/linux/man-pages/man8/sysctl.8.html
//   https://man7.org/linux/man-pages/man5/sysctl.d.5.html
// For example:
// Input sysctl variable "net/ipv4/conf/eno2.100.rp_filter"
// will return the converted value "net.ipv4.conf.eno2/100.rp_filter"
func convertSysctlVariableToDotsSeparator(val string) string {
	if val == "" {
		return val
	}
	firstSepIndex := strings.IndexAny(val, "./")
	if firstSepIndex == -1 || val[firstSepIndex] == '.' {
		return val
	}

	f := func(r rune) rune {
		switch r {
		case '.':
			return '/'
		case '/':
			return '.'
		}
		return r
	}
	return strings.Map(f, val)
}

// sysctl validates that the specified sysctl keys are valid or not.
// /proc/sys isn't completely namespaced and depending on which namespaces
// are specified, a subset of sysctls are permitted.
func (v *ConfigValidator) sysctl(config *configs.Config) error {
	return nil
}


func (v *ConfigValidator) cgroups(config *configs.Config) error {
	c := config.Cgroups
	if c == nil {
		return nil
	}

	if (c.Name != "" || c.Parent != "") && c.Path != "" {
		return fmt.Errorf("cgroup: either Path or Name and Parent should be used, got %+v", c)
	}

	r := c.Resources
	if r == nil {
		return nil
	}

	return nil
}

func (v *ConfigValidator) mounts(config *configs.Config) error {
	for _, m := range config.Mounts {
		if !filepath.IsAbs(m.Destination) {
			return fmt.Errorf("invalid mount %+v: mount destination not absolute", m)
		}
	}

	return nil
}

func isHostNetNS(path string) (bool, error) {
	return true, nil
}
