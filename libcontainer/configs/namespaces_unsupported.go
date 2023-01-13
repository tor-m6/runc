//go:build !linux
// +build !linux

package configs

// Namespace defines configuration for each namespace.  It specifies an
// alternate path that is able to be joined via setns.
type Namespace struct{}

func NamespaceTypes() []NamespaceType {
	return []NamespaceType{
		NEWUSER, // Keep user NS always first, don't move it.
		NEWIPC,
		NEWUTS,
		NEWNET,
		NEWPID,
		NEWNS,
		NEWCGROUP,
	}
}

func IsNamespaceSupported(ns NamespaceType) bool {
	return false
}

// NsName converts the namespace type to its filename
func NsName(ns NamespaceType) string {
	switch ns {
	case NEWNET:
		return "net"
	case NEWNS:
		return "mnt"
	case NEWPID:
		return "pid"
	case NEWIPC:
		return "ipc"
	case NEWUSER:
		return "user"
	case NEWUTS:
		return "uts"
	case NEWCGROUP:
		return "cgroup"
	}
	return ""
}
