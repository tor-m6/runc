package libcontainer

import (
	// "bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"strconv"
	"syscall"
	// "unsafe"

	"github.com/containerd/console"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/capabilities"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/system"
	"github.com/opencontainers/runc/libcontainer/user"
	"github.com/opencontainers/runc/libcontainer/utils"
)

type initType string

const (
	initSetns    initType = "setns"
	initStandard initType = "standard"
)

type pid struct {
	Pid           int `json:"stage2_pid"`
	PidFirstChild int `json:"stage1_pid"`
}

// network is an internal struct used to setup container networks.
type network struct {
	configs.Network

	// TempVethPeerName is a unique temporary veth peer name that was placed into
	// the container's namespace.
	TempVethPeerName string `json:"temp_veth_peer_name"`
}

// initConfig is used for transferring parameters from Exec() to Init()
type initConfig struct {
	Args             []string              `json:"args"`
	Env              []string              `json:"env"`
	Cwd              string                `json:"cwd"`
	Capabilities     *configs.Capabilities `json:"capabilities"`
	ProcessLabel     string                `json:"process_label"`
	AppArmorProfile  string                `json:"apparmor_profile"`
	NoNewPrivileges  bool                  `json:"no_new_privileges"`
	User             string                `json:"user"`
	AdditionalGroups []string              `json:"additional_groups"`
	Config           *configs.Config       `json:"config"`
	Networks         []*network            `json:"network"`
	PassedFilesCount int                   `json:"passed_files_count"`
	ContainerID      string                `json:"containerid"`
	Rlimits          []configs.Rlimit      `json:"rlimits"`
	CreateConsole    bool                  `json:"create_console"`
	ConsoleWidth     uint16                `json:"console_width"`
	ConsoleHeight    uint16                `json:"console_height"`
	RootlessEUID     bool                  `json:"rootless_euid,omitempty"`
	RootlessCgroups  bool                  `json:"rootless_cgroups,omitempty"`
	SpecState        *specs.State          `json:"spec_state,omitempty"`
	Cgroup2Path      string                `json:"cgroup2_path,omitempty"`
}

type initer interface {
	Init() error
}

// linuxSetnsInit performs the container's initialization for running a new process
// inside an existing container.
type linuxSetnsInit struct {
	pipe          *os.File
	consoleSocket *os.File
	config        *initConfig
	logFd         int
}

type linuxStandardInit struct {
	pipe          *os.File
	consoleSocket *os.File
	parentPid     int
	fifoFd        int
	logFd         int
	mountFds      []int
	config        *initConfig
}

func newContainerInit(t initType, pipe *os.File, consoleSocket *os.File, fifoFd, logFd int, mountFds []int) (initer, error) {
	var config *initConfig
	if err := json.NewDecoder(pipe).Decode(&config); err != nil {
		return nil, err
	}
	if err := populateProcessEnvironment(config.Env); err != nil {
		return nil, err
	}
	switch t {
	case initSetns:
		// mountFds must be nil in this case. We don't mount while doing runc exec.
		if mountFds != nil {
			return nil, errors.New("mountFds must be nil; can't mount from exec")
		}

		// return &linuxSetnsInit{
		// 	pipe:          pipe,
		// 	consoleSocket: consoleSocket,
		// 	config:        config,
		// 	logFd:         logFd,
		// }, nil
		return nil,nil
	case initStandard:
		return &linuxStandardInit{
			pipe:          pipe,
			consoleSocket: consoleSocket,
			parentPid:     unix.Getppid(),
			config:        config,
			fifoFd:        fifoFd,
			logFd:         logFd,
			mountFds:      mountFds,
		}, nil
	}
	return nil, fmt.Errorf("unknown init type %q", t)
}

// populateProcessEnvironment loads the provided environment variables into the
// current processes's environment.
func populateProcessEnvironment(env []string) error {
	for _, pair := range env {
		p := strings.SplitN(pair, "=", 2)
		if len(p) < 2 {
			return fmt.Errorf("invalid environment variable: %q", pair)
		}
		name, val := p[0], p[1]
		if name == "" {
			return fmt.Errorf("environment variable name can't be empty: %q", pair)
		}
		if strings.IndexByte(name, 0) >= 0 {
			return fmt.Errorf("environment variable name can't contain null(\\x00): %q", pair)
		}
		if strings.IndexByte(val, 0) >= 0 {
			return fmt.Errorf("environment variable value can't contain null(\\x00): %q", pair)
		}
		if err := os.Setenv(name, val); err != nil {
			return err
		}
	}
	return nil
}

// finalizeNamespace drops the caps, sets the correct user
// and working dir, and closes any leaked file descriptors
// before executing the command inside the namespace
func finalizeNamespace(config *initConfig) error {
	// Ensure that all unwanted fds we may have accidentally
	// inherited are marked close-on-exec so they stay out of the
	// container
	if err := utils.CloseExecFrom(config.PassedFilesCount + 3); err != nil {
		return fmt.Errorf("error closing exec fds: %w", err)
	}

	// we only do chdir if it's specified
	doChdir := config.Cwd != ""
	if doChdir {
		// First, attempt the chdir before setting up the user.
		// This could allow us to access a directory that the user running runc can access
		// but the container user cannot.
		err := unix.Chdir(config.Cwd)
		switch {
		case err == nil:
			doChdir = false
		case os.IsPermission(err):
			// If we hit an EPERM, we should attempt again after setting up user.
			// This will allow us to successfully chdir if the container user has access
			// to the directory, but the user running runc does not.
			// This is useful in cases where the cwd is also a volume that's been chowned to the container user.
		default:
			return fmt.Errorf("chdir to cwd (%q) set in config.json failed: %w", config.Cwd, err)
		}
	}

	caps := &configs.Capabilities{}
	if config.Capabilities != nil {
		caps = config.Capabilities
	} else if config.Config.Capabilities != nil {
		caps = config.Config.Capabilities
	}
	_, err := capabilities.New(caps)
	if err != nil {
		return err
	}
	// drop capabilities in bounding set before changing user
	// if err := w.ApplyBoundingSet(); err != nil {
	// 	return fmt.Errorf("unable to apply bounding set: %w", err)
	// }
	// preserve existing capabilities while we change users
	// if err := system.SetKeepCaps(); err != nil {
	// 	return fmt.Errorf("unable to set keep caps: %w", err)
	// }
	if err := setupUser(config); err != nil {
		return fmt.Errorf("unable to setup user: %w", err)
	}
	// Change working directory AFTER the user has been set up, if we haven't done it yet.
	if doChdir {
		if err := unix.Chdir(config.Cwd); err != nil {
			return fmt.Errorf("chdir to cwd (%q) set in config.json failed: %w", config.Cwd, err)
		}
	}
	// if err := system.ClearKeepCaps(); err != nil {
	// 	return fmt.Errorf("unable to clear keep caps: %w", err)
	// }
	// if err := w.ApplyCaps(); err != nil {
	// 	return fmt.Errorf("unable to apply caps: %w", err)
	// }
	return nil
}

// setupConsole sets up the console from inside the container, and sends the
// master pty fd to the config.Pipe (using cmsg). This is done to ensure that
// consoles are scoped to a container properly (see runc#814 and the many
// issues related to that). This has to be run *after* we've pivoted to the new
// rootfs (and the users' configuration is entirely set up).
func setupConsole(socket *os.File, config *initConfig, mount bool) error {
	defer socket.Close()
	// At this point, /dev/ptmx points to something that we would expect. We
	// used to change the owner of the slave path, but since the /dev/pts mount
	// can have gid=X set (at the users' option). So touching the owner of the
	// slave PTY is not necessary, as the kernel will handle that for us. Note
	// however, that setupUser (specifically fixStdioPermissions) *will* change
	// the UID owner of the console to be the user the process will run as (so
	// they can actually control their console).

	pty, slavePath, err := console.NewPty()
	if err != nil {
		return err
	}

	// After we return from here, we don't need the console anymore.
	defer pty.Close()

	if config.ConsoleHeight != 0 && config.ConsoleWidth != 0 {
		err = pty.Resize(console.WinSize{
			Height: config.ConsoleHeight,
			Width:  config.ConsoleWidth,
		})

		if err != nil {
			return err
		}
	}

	// Mount the console inside our rootfs.
	if mount {
		if err := mountConsole(slavePath); err != nil {
			return err
		}
	}
	// While we can access console.master, using the API is a good idea.
	if err := utils.SendFd(socket, pty.Name(), pty.Fd()); err != nil {
		return err
	}
	// Now, dup over all the things.
	return dupStdio(slavePath)
}

// syncParentReady sends to the given pipe a JSON payload which indicates that
// the init is ready to Exec the child process. It then waits for the parent to
// indicate that it is cleared to Exec.
func syncParentReady(pipe io.ReadWriter) error {
	// Tell parent.
	if err := writeSync(pipe, procReady); err != nil {
		return err
	}

	// Wait for parent to give the all-clear.
	return readSync(pipe, procRun)
}

// syncParentHooks sends to the given pipe a JSON payload which indicates that
// the parent should execute pre-start hooks. It then waits for the parent to
// indicate that it is cleared to resume.
func syncParentHooks(pipe io.ReadWriter) error {
	// Tell parent.
	if err := writeSync(pipe, procHooks); err != nil {
		return err
	}

	// Wait for parent to give the all-clear.
	return readSync(pipe, procResume)
}

// syncParentSeccomp sends to the given pipe a JSON payload which
// indicates that the parent should pick up the seccomp fd with pidfd_getfd()
// and send it to the seccomp agent over a unix socket. It then waits for
// the parent to indicate that it is cleared to resume and closes the seccompFd.
// If the seccompFd is -1, there isn't anything to sync with the parent, so it
// returns no error.
func syncParentSeccomp(pipe io.ReadWriter, seccompFd int) error {
	if seccompFd == -1 {
		return nil
	}

	// Tell parent.
	if err := writeSyncWithFd(pipe, procSeccomp, seccompFd); err != nil {
		unix.Close(seccompFd)
		return err
	}

	// Wait for parent to give the all-clear.
	if err := readSync(pipe, procSeccompDone); err != nil {
		unix.Close(seccompFd)
		return fmt.Errorf("sync parent seccomp: %w", err)
	}

	if err := unix.Close(seccompFd); err != nil {
		return fmt.Errorf("close seccomp fd: %w", err)
	}

	return nil
}

// setupUser changes the groups, gid, and uid for the user inside the container
func setupUser(config *initConfig) error {
	return nil
}

// fixStdioPermissions fixes the permissions of PID 1's STDIO within the container to the specified user.
// The ownership needs to match because it is created outside of the container and needs to be
// localized.
func fixStdioPermissions(u *user.ExecUser) error {
	// var null unix.Stat_t
	// if err := unix.Stat("/dev/null", &null); err != nil {
	// 	return &os.PathError{Op: "stat", Path: "/dev/null", Err: err}
	// }
	// for _, file := range []*os.File{os.Stdin, os.Stdout, os.Stderr} {
	// 	var s unix.Stat_t
	// 	if err := unix.Fstat(int(file.Fd()), &s); err != nil {
	// 		return &os.PathError{Op: "fstat", Path: file.Name(), Err: err}
	// 	}

	// 	// Skip chown if uid is already the one we want.
	// 	if int(s.Uid) == u.Uid {
	// 		continue
	// 	}

	// 	// We only change the uid (as it is possible for the mount to
	// 	// prefer a different gid, and there's no reason for us to change it).
	// 	// The reason why we don't just leave the default uid=X mount setup is
	// 	// that users expect to be able to actually use their console. Without
	// 	// this code, you couldn't effectively run as a non-root user inside a
	// 	// container and also have a console set up.
	// 	if err := file.Chown(u.Uid, int(s.Gid)); err != nil {
	// 		// If we've hit an EINVAL then s.Gid isn't mapped in the user
	// 		// namespace. If we've hit an EPERM then the inode's current owner
	// 		// is not mapped in our user namespace (in particular,
	// 		// privileged_wrt_inode_uidgid() has failed). Read-only
	// 		// /dev can result in EROFS error. In any case, it's
	// 		// better for us to just not touch the stdio rather
	// 		// than bail at this point.

	// 		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EROFS) {
	// 			continue
	// 		}
	// 		return err
	// 	}
	// }
	return nil
}

// setupNetwork sets up and initializes any network interface inside the container.
func setupNetwork(config *initConfig) error {
	for _, config := range config.Networks {
		strategy, err := getStrategy(config.Type)
		if err != nil {
			return err
		}
		if err := strategy.initialize(config); err != nil {
			return err
		}
	}
	return nil
}

func setupRoute(config *configs.Config) error {
	for _, config := range config.Routes {
		_, dst, err := net.ParseCIDR(config.Destination)
		if err != nil {
			return err
		}
		src := net.ParseIP(config.Source)
		if src == nil {
			return fmt.Errorf("Invalid source for route: %s", config.Source)
		}
		gw := net.ParseIP(config.Gateway)
		if gw == nil {
			return fmt.Errorf("Invalid gateway for route: %s", config.Gateway)
		}
		l, err := netlink.LinkByName(config.InterfaceName)
		if err != nil {
			return err
		}
		route := &netlink.Route{
			Scope:     netlink.SCOPE_UNIVERSE,
			Dst:       dst,
			Src:       src,
			Gw:        gw,
			LinkIndex: l.Attrs().Index,
		}
		if err := netlink.RouteAdd(route); err != nil {
			return err
		}
	}
	return nil
}

func setupRlimits(limits []configs.Rlimit, pid int) error {
	// for _, rlimit := range limits {
	// 	if err := unix.Prlimit(pid, rlimit.Type, &unix.Rlimit{Max: rlimit.Hard, Cur: rlimit.Soft}, nil); err != nil {
	// 		return fmt.Errorf("error setting rlimit type %v: %w", rlimit.Type, err)
	// 	}
	// }
	return nil
}

const _P_PID = 1

//nolint:structcheck,unused
type siginfo struct {
	si_signo int32
	si_errno int32
	si_code  int32
	// below here is a union; si_pid is the only field we use
	si_pid int32
	// Pad to 128 bytes as detailed in blockUntilWaitable
	pad [96]byte
}

// isWaitable returns true if the process has exited false otherwise.
// Its based off blockUntilWaitable in src/os/wait_waitid.go
func isWaitable(pid int) (bool, error) {
	// si := &siginfo{}
	// _, _, e := unix.Syscall6(unix.SYS_WAITID, _P_PID, uintptr(pid), uintptr(unsafe.Pointer(si)), unix.WEXITED|unix.WNOWAIT|unix.WNOHANG, 0, 0)
	// if e != 0 {
	// 	return false, &os.SyscallError{Syscall: "waitid", Err: e}
	// }

	// return si.si_pid != 0, nil
	return false, nil
}

// signalAllProcesses freezes then iterates over all the processes inside the
// manager's cgroups sending the signal s to them.
// If s is SIGKILL then it will wait for each process to exit.
// For all other signals it will check if the process is ready to report its
// exit status and only if it is will a wait be performed.
func signalAllProcesses(m cgroups.Manager, s os.Signal) error {
	// var procs []*os.Process
	// if err := m.Freeze(configs.Frozen); err != nil {
	// 	logrus.Warn(err)
	// }
	// pids, err := m.GetAllPids()
	// if err != nil {
	// 	if err := m.Freeze(configs.Thawed); err != nil {
	// 		logrus.Warn(err)
	// 	}
	// 	return err
	// }
	// for _, pid := range pids {
	// 	p, err := os.FindProcess(pid)
	// 	if err != nil {
	// 		logrus.Warn(err)
	// 		continue
	// 	}
	// 	procs = append(procs, p)
	// 	if err := p.Signal(s); err != nil {
	// 		logrus.Warn(err)
	// 	}
	// }
	// if err := m.Freeze(configs.Thawed); err != nil {
	// 	logrus.Warn(err)
	// }

	// subreaper, err := system.GetSubreaper()
	// if err != nil {
	// 	// The error here means that PR_GET_CHILD_SUBREAPER is not
	// 	// supported because this code might run on a kernel older
	// 	// than 3.4. We don't want to throw an error in that case,
	// 	// and we simplify things, considering there is no subreaper
	// 	// set.
	// 	subreaper = 0
	// }

	// for _, p := range procs {
	// 	if s != unix.SIGKILL {
	// 		if ok, err := isWaitable(p.Pid); err != nil {
	// 			if !errors.Is(err, unix.ECHILD) {
	// 				logrus.Warn("signalAllProcesses: ", p.Pid, err)
	// 			}
	// 			continue
	// 		} else if !ok {
	// 			// Not ready to report so don't wait
	// 			continue
	// 		}
	// 	}

	// 	// In case a subreaper has been setup, this code must not
	// 	// wait for the process. Otherwise, we cannot be sure the
	// 	// current process will be reaped by the subreaper, while
	// 	// the subreaper might be waiting for this process in order
	// 	// to retrieve its exit code.
	// 	if subreaper == 0 {
	// 		if _, err := p.Wait(); err != nil {
	// 			if !errors.Is(err, unix.ECHILD) {
	// 				logrus.Warn("wait: ", err)
	// 			}
	// 		}
	// 	}
	// }
	return nil
}

func (l *linuxStandardInit) Init() error {
	// if !l.config.Config.NoNewKeyring {
	// 	if err := selinux.SetKeyLabel(l.config.ProcessLabel); err != nil {
	// 		return err
	// 	}
	// 	defer selinux.SetKeyLabel("") //nolint: errcheck
	// 	ringname, keepperms, newperms := l.getSessionRingParams()

	// 	// Do not inherit the parent's session keyring.
	// 	if sessKeyId, err := keys.JoinSessionKeyring(ringname); err != nil {
	// 		// If keyrings aren't supported then it is likely we are on an
	// 		// older kernel (or inside an LXC container). While we could bail,
	// 		// the security feature we are using here is best-effort (it only
	// 		// really provides marginal protection since VFS credentials are
	// 		// the only significant protection of keyrings).
	// 		//
	// 		// TODO(cyphar): Log this so people know what's going on, once we
	// 		//               have proper logging in 'runc init'.
	// 		if !errors.Is(err, unix.ENOSYS) {
	// 			return fmt.Errorf("unable to join session keyring: %w", err)
	// 		}
	// 	} else {
	// 		// Make session keyring searchable. If we've gotten this far we
	// 		// bail on any error -- we don't want to have a keyring with bad
	// 		// permissions.
	// 		if err := keys.ModKeyringPerm(sessKeyId, keepperms, newperms); err != nil {
	// 			return fmt.Errorf("unable to mod keyring permissions: %w", err)
	// 		}
	// 	}
	// }

	if err := setupNetwork(l.config); err != nil {
		return err
	}
	if err := setupRoute(l.config.Config); err != nil {
		return err
	}

	// initialises the labeling system
	// selinux.GetEnabled()

	// We don't need the mountFds after prepareRootfs() nor if it fails.
	// err := prepareRootfs(l.pipe, l.config, l.mountFds)
	// for _, m := range l.mountFds {
	// 	if m == -1 {
	// 		continue
	// 	}

	// 	if err := unix.Close(m); err != nil {
	// 		return fmt.Errorf("Unable to close mountFds fds: %w", err)
	// 	}
	// }

	// if err != nil {
	// 	return err
	// }

	// Set up the console. This has to be done *before* we finalize the rootfs,
	// but *after* we've given the user the chance to set up all of the mounts
	// they wanted.
	if l.config.CreateConsole {
		if err := setupConsole(l.consoleSocket, l.config, true); err != nil {
			return err
		}
		if err := unix.IoctlSetInt(0, unix.TIOCSCTTY, 0); err != nil {
			return &os.SyscallError{Syscall: "ioctl(setctty)", Err: err}
		}
	}

	// Finish the rootfs setup.
	// if l.config.Config.Namespaces.Contains(configs.NEWNS) {
	// 	if err := finalizeRootfs(l.config.Config); err != nil {
	// 		return err
	// 	}
	// }

	if hostname := l.config.Config.Hostname; hostname != "" {
		if err := syscall.Sethostname([]byte(hostname)); err != nil {
			return &os.SyscallError{Syscall: "sethostname", Err: err}
		}
	}
	// if err := apparmor.ApplyProfile(l.config.AppArmorProfile); err != nil {
	// 	return fmt.Errorf("unable to apply apparmor profile: %w", err)
	// }

	// for key, value := range l.config.Config.Sysctl {
	// 	if err := writeSystemProperty(key, value); err != nil {
	// 		return err
	// 	}
	// }
	// for _, path := range l.config.Config.ReadonlyPaths {
	// 	if err := readonlyPath(path); err != nil {
	// 		return fmt.Errorf("can't make %q read-only: %w", path, err)
	// 	}
	// }
	// for _, path := range l.config.Config.MaskPaths {
	// 	if err := maskPath(path, l.config.Config.MountLabel); err != nil {
	// 		return fmt.Errorf("can't mask path %s: %w", path, err)
	// 	}
	// }
	// pdeath, err := system.GetParentDeathSignal()
	// if err != nil {
	// 	return fmt.Errorf("can't get pdeath signal: %w", err)
	// }
	// if l.config.NoNewPrivileges {
	// 	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
	// 		return &os.SyscallError{Syscall: "prctl(SET_NO_NEW_PRIVS)", Err: err}
	// 	}
	// }
	// Tell our parent that we're ready to Execv. This must be done before the
	// Seccomp rules have been applied, because we need to be able to read and
	// write to a socket.
	if err := syncParentReady(l.pipe); err != nil {
		return fmt.Errorf("sync ready: %w", err)
	}
	// if err := selinux.SetExecLabel(l.config.ProcessLabel); err != nil {
	// 	return fmt.Errorf("can't set process label: %w", err)
	// }
	// defer selinux.SetExecLabel("") //nolint: errcheck
	// Without NoNewPrivileges seccomp is a privileged operation, so we need to
	// do this before dropping capabilities; otherwise do it as late as possible
	// just before execve so as few syscalls take place after it as possible.
	// if l.config.Config.Seccomp != nil && !l.config.NoNewPrivileges {
	// 	seccompFd, err := seccomp.InitSeccomp(l.config.Config.Seccomp)
	// 	if err != nil {
	// 		return err
	// 	}

	// 	if err := syncParentSeccomp(l.pipe, seccompFd); err != nil {
	// 		return err
	// 	}
	// }
	// if err := finalizeNamespace(l.config); err != nil {
	// 	return err
	// }
	// finalizeNamespace can change user/group which clears the parent death
	// signal, so we restore it here.
	// if err := pdeath.Restore(); err != nil {
	// 	return fmt.Errorf("can't restore pdeath signal: %w", err)
	// }
	// Compare the parent from the initial start of the init process and make
	// sure that it did not change.  if the parent changes that means it died
	// and we were reparented to something else so we should just kill ourself
	// and not cause problems for someone else.
	if unix.Getppid() != l.parentPid {
		return unix.Kill(syscall.Getpid(), unix.SIGKILL)
	}
	// Check for the arg before waiting to make sure it exists and it is
	// returned as a create time error.
	name, err := exec.LookPath(l.config.Args[0])
	if err != nil {
		return err
	}
	// Set seccomp as close to execve as possible, so as few syscalls take
	// place afterward (reducing the amount of syscalls that users need to
	// enable in their seccomp profiles). However, this needs to be done
	// before closing the pipe since we need it to pass the seccompFd to
	// the parent.
	// if l.config.Config.Seccomp != nil && l.config.NoNewPrivileges {
	// 	seccompFd, err := seccomp.InitSeccomp(l.config.Config.Seccomp)
	// 	if err != nil {
	// 		return fmt.Errorf("unable to init seccomp: %w", err)
	// 	}

	// 	if err := syncParentSeccomp(l.pipe, seccompFd); err != nil {
	// 		return err
	// 	}
	// }
	// Close the pipe to signal that we have completed our init.
	logrus.Debugf("init: closing the pipe to signal completion")
	_ = l.pipe.Close()

	// Close the log pipe fd so the parent's ForwardLogs can exit.
	if err := unix.Close(l.logFd); err != nil {
		return &os.PathError{Op: "close log pipe", Path: "fd " + strconv.Itoa(l.logFd), Err: err}
	}

	// Wait for the FIFO to be opened on the other side before exec-ing the
	// user process. We open it through /proc/self/fd/$fd, because the fd that
	// was given to us was an O_PATH fd to the fifo itself. Linux allows us to
	// re-open an O_PATH fd through /proc.
	fifoPath := "/proc/self/fd/" + strconv.Itoa(l.fifoFd)
	fd, err := syscall.Open(fifoPath, unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return &os.PathError{Op: "open exec fifo", Path: fifoPath, Err: err}
	}
	if _, err := unix.Write(fd, []byte("0")); err != nil {
		return &os.PathError{Op: "write exec fifo", Path: fifoPath, Err: err}
	}

	// Close the O_PATH fifofd fd before exec because the kernel resets
	// dumpable in the wrong order. This has been fixed in newer kernels, but
	// we keep this to ensure CVE-2016-9962 doesn't re-emerge on older kernels.
	// N.B. the core issue itself (passing dirfds to the host filesystem) has
	// since been resolved.
	// https://github.com/torvalds/linux/blob/v4.9/fs/exec.c#L1290-L1318
	_ = unix.Close(l.fifoFd)

	s := l.config.SpecState
	s.Pid = syscall.Getpid()
	s.Status = specs.StateCreated
	if err := l.config.Config.Hooks[configs.StartContainer].RunHooks(s); err != nil {
		return err
	}

	return system.Exec(name, l.config.Args[0:], os.Environ())
}
