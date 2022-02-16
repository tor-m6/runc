//go:build !linux
// +build !linux

package capabilities

import (
	"github.com/opencontainers/runc/libcontainer/configs"
	// "github.com/sirupsen/logrus"
	"github.com/syndtr/gocapability/capability"
)

// Caps holds the capabilities for a container.
type Caps struct {
	pid  capability.Capabilities
	caps map[capability.CapType][]capability.Cap
}

func New(capConfig *configs.Capabilities) (*Caps, error) {
	return nil,nil
}
