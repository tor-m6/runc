// +build !linux

package netlink

import (
	"golang.org/x/sys/unix"
)

func (r *Route) ListFlags() []string {
	return []string{}
}

func (n *NexthopInfo) ListFlags() []string {
	return []string{}
}

const (
	SCOPE_UNIVERSE Scope = unix.RT_SCOPE_UNIVERSE
	SCOPE_SITE     Scope = unix.RT_SCOPE_SITE
	SCOPE_LINK     Scope = unix.RT_SCOPE_LINK
	SCOPE_HOST     Scope = unix.RT_SCOPE_HOST
	SCOPE_NOWHERE  Scope = unix.RT_SCOPE_NOWHERE
)
