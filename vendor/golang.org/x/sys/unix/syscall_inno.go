// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Linux system calls.
// This file is compiled as ordinary Go code,
// but it is also input to mksyscall,
// which parses the //sys lines and generates system call stubs.
// Note that sometimes we use a lowercase //sys name and
// wrap it in our own nicer implementation.

package unix

import (
	"unsafe"
	"sort"
	"sync"
	"encoding/binary"
	"syscall"
)

const (
	IP_RECVDSTADDR = syscall.IP_RECVDSTADDR
)

var (
	signalNameMapOnce sync.Once
	signalNameMap     map[string]syscall.Signal
)

type Signal = syscall.Signal
type Errno = syscall.Errno
type SysProcAttr = syscall.SysProcAttr

//sys	utimensat(dirfd int, path string, times *[2]Timespec, flags int) (err error)
func utimensat(dirfd int, path string, times *[2]Timespec, flags int) error {
	// Darwin doesn't support SYS_UTIMENSAT
	return syscall.ENOSYS
}

func setTimespec(sec, nsec int64) Timespec {
	return Timespec{Sec: sec, Nsec: nsec}
}

func setTimeval(sec, usec int64) Timeval {
	return Timeval{Sec: sec, Usec: usec}
}

func (iov *Iovec) SetLen(length int) {
	iov.Len = uint64(length)
}

func (cmsg *Cmsghdr) SetLen(length int) {
	cmsg.Len = uint64(length)
}


// Automatically generated wrapper for utimes/utimes
//extern utimes
func c_utimes(path *byte, times *[2]Timeval) _C_int
func utimes(path string, times *[2]Timeval) (err error) {
	var _p1 *byte
	_p1, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	syscall.Entersyscall()
	_r := c_utimes(_p1, times)
	var errno syscall.Errno
	setErrno := false
	if _r < 0 {
		errno = syscall.GetErrno()
		setErrno = true
	}
	syscall.Exitsyscall()
	if setErrno {
		err = errno
	}
	return
}

func Utimes(path string, tv []Timeval) error {
	if tv == nil {
		err := utimensat(AT_FDCWD, path, nil, 0)
		if err != syscall.ENOSYS {
			return err
		}
		return syscall.Utimes(path, nil)
	}
	if len(tv) != 2 {
		return syscall.EINVAL
	}
	var ts [2]Timespec
	ts[0] = NsecToTimespec(TimevalToNsec(tv[0]))
	ts[1] = NsecToTimespec(TimevalToNsec(tv[1]))
	err := utimensat(AT_FDCWD, path, (*[2]Timespec)(unsafe.Pointer(&ts[0])), 0)
	if err != syscall.ENOSYS {
		return err
	}
	return utimes(path, (*[2]Timeval)(unsafe.Pointer(&tv[0])))
}


func UtimesNano(path string, ts []Timespec) error {
	if ts == nil {
		err := utimensat(AT_FDCWD, path, nil, 0)
		if err != syscall.ENOSYS {
			return err
		}
		return syscall.Utimes(path, nil)
	}
	if len(ts) != 2 {
		return syscall.EINVAL
	}
	err := utimensat(AT_FDCWD, path, (*[2]Timespec)(unsafe.Pointer(&ts[0])), 0)
	if err != syscall.ENOSYS {
		return err
	}
	// If the utimensat syscall isn't available (utimensat was added to Linux
	// in 2.6.22, Released, 8 July 2007) then fall back to utimes
	var tv [2]Timeval
	for i := 0; i < 2; i++ {
		tv[i] = NsecToTimeval(TimespecToNsec(ts[i]))
	}
	return utimes(path, (*[2]Timeval)(unsafe.Pointer(&tv[0])))
}

func UtimesNanoAt(dirfd int, path string, ts []Timespec, flags int) error {
	if ts == nil {
		return utimensat(dirfd, path, nil, flags)
	}
	if len(ts) != 2 {
		return syscall.EINVAL
	}
	return utimensat(dirfd, path, (*[2]Timespec)(unsafe.Pointer(&ts[0])), flags)
}

// SignalName returns the signal name for signal number s.
func SignalName(s syscall.Signal) string {
	i := sort.Search(len(signalList), func(i int) bool {
		return signalList[i].num >= s
	})
	if i < len(signalList) && signalList[i].num == s {
		return signalList[i].name
	}
	return ""
}

// SignalNum returns the syscall.Signal for signal named s,
// or 0 if a signal with such name is not found.
// The signal name should start with "SIG".
func SignalNum(s string) syscall.Signal {
	signalNameMapOnce.Do(func() {
		signalNameMap = make(map[string]syscall.Signal)
		for _, signal := range signalList {
			signalNameMap[signal.name] = signal.num
		}
	})
	return signalNameMap[s]
}

func Recvmsg(fd int, p, oob []byte, flags int) (n, oobn int, recvflags int, from Sockaddr, err error) {
	var msg Msghdr
	var rsa RawSockaddrAny
	msg.Name = (*byte)(unsafe.Pointer(&rsa))
	msg.Namelen = uint32(SizeofSockaddrAny)
	var iov Iovec
	if len(p) > 0 {
		iov.Base = &p[0]
		iov.SetLen(len(p))
	}
	var dummy byte
	if len(oob) > 0 {
		if len(p) == 0 {
			var sockType int
			sockType, err = GetsockoptInt(fd, SOL_SOCKET, SO_TYPE)
			if err != nil {
				return
			}
			// receive at least one normal byte
			if sockType != SOCK_DGRAM {
				iov.Base = &dummy
				iov.SetLen(1)
			}
		}
		msg.Control = &oob[0]
		msg.SetControllen(len(oob))
	}
	msg.Iov = &iov
	msg.Iovlen = 1
	if n, err = recvmsg(fd, &msg, flags); err != nil {
		return
	}
	oobn = int(msg.Controllen)
	recvflags = int(msg.Flags)
	// source address is only specified if the socket is unconnected
	if rsa.Addr.Family != AF_UNSPEC {
		from, err = anyToSockaddr(fd, &rsa)
	}
	return
}

func Sendmsg(fd int, p, oob []byte, to Sockaddr, flags int) (err error) {
	_, err = SendmsgN(fd, p, oob, to, flags)
	return
}

func SendmsgN(fd int, p, oob []byte, to Sockaddr, flags int) (n int, err error) {
	var ptr unsafe.Pointer
	var salen _Socklen
	if to != nil {
		var err error
		ptr, salen, err = to.sockaddr()
		if err != nil {
			return 0, err
		}
	}
	var msg Msghdr
	msg.Name = (*byte)(ptr)
	msg.Namelen = uint32(salen)
	var iov Iovec
	if len(p) > 0 {
		iov.Base = &p[0]
		iov.SetLen(len(p))
	}
	var dummy byte
	if len(oob) > 0 {
		if len(p) == 0 {
			var sockType int
			sockType, err = GetsockoptInt(fd, SOL_SOCKET, SO_TYPE)
			if err != nil {
				return 0, err
			}
			// send at least one normal byte
			if sockType != SOCK_DGRAM {
				iov.Base = &dummy
				iov.SetLen(1)
			}
		}
		msg.Control = &oob[0]
		msg.SetControllen(len(oob))
	}
	msg.Iov = &iov
	msg.Iovlen = 1
	if n, err = sendmsg(fd, &msg, flags); err != nil {
		return 0, err
	}
	if len(oob) > 0 && len(p) == 0 {
		n = 0
	}
	return n, nil
}

func GetsockoptByte(fd, level, opt int) (value byte, err error) {
	var n byte
	vallen := syscall.Socklen_t(1)
	err = getsockopt(fd, level, opt, unsafe.Pointer(&n), &vallen)
	return n, err
}

func GetsockoptInt(fd, level, opt int) (value int, err error) {
	var n int32
	vallen := syscall.Socklen_t(4)
	err = getsockopt(fd, level, opt, unsafe.Pointer(&n), &vallen)
	return int(n), err
}

func (msghdr *Msghdr) SetControllen(length int) {
	msghdr.Controllen = uint64(length)
}

// Automatically generated wrapper for getsockopt/getsockopt
//extern getsockopt
func c_getsockopt(s _C_int, level _C_int, name _C_int, val *byte, vallen *syscall.Socklen_t) _C_int
func getsockopt(s int, level int, name int, val unsafe.Pointer, vallen *syscall.Socklen_t) (err error) {
	syscall.Entersyscall()
	_r := c_getsockopt(_C_int(s), _C_int(level), _C_int(name), (*byte)(val), vallen)
	var errno syscall.Errno
	setErrno := false
	if _r < 0 {
		errno = syscall.GetErrno()
		setErrno = true
	}
	syscall.Exitsyscall()
	if setErrno {
		err = errno
	}
	return
}

// Automatically generated wrapper for sendmsg/sendmsg
//extern sendmsg
func c_sendmsg(s _C_int, msg *Msghdr, flags _C_int) syscall.Ssize_t
func sendmsg(s int, msg *Msghdr, flags int) (n int, err error) {
	syscall.Entersyscall()
	_r := c_sendmsg(_C_int(s), msg, _C_int(flags))
	n = (int)(_r)
	var errno syscall.Errno
	setErrno := false
	if _r < 0 {
		errno = syscall.GetErrno()
		setErrno = true
	}
	syscall.Exitsyscall()
	if setErrno {
		err = errno
	}
	return
}

// Automatically generated wrapper for recvmsg/recvmsg
//extern recvmsg
func c_recvmsg(s _C_int, msg *Msghdr, flags _C_int) syscall.Ssize_t
func recvmsg(s int, msg *Msghdr, flags int) (n int, err error) {
	syscall.Entersyscall()
	_r := c_recvmsg(_C_int(s), msg, _C_int(flags))
	n = (int)(_r)
	var errno syscall.Errno
	setErrno := false
	if _r < 0 {
		errno = syscall.GetErrno()
		setErrno = true
	}
	syscall.Exitsyscall()
	if setErrno {
		err = errno
	}
	return
}

// SockaddrLinklayer implements the Sockaddr interface for AF_PACKET type sockets.
type SockaddrLinklayer struct {
	Protocol uint16
	Ifindex  int
	Hatype   uint16
	Pkttype  uint8
	Halen    uint8
	Addr     [8]byte
	raw      RawSockaddrLinklayer
}

func (sa *SockaddrLinklayer) sockaddr() (unsafe.Pointer, _Socklen, error) {
	if sa.Ifindex < 0 || sa.Ifindex > 0x7fffffff {
		return nil, 0, EINVAL
	}
	sa.raw.Family = AF_PACKET
	sa.raw.Protocol = sa.Protocol
	sa.raw.Ifindex = int32(sa.Ifindex)
	sa.raw.Hatype = sa.Hatype
	sa.raw.Pkttype = sa.Pkttype
	sa.raw.Halen = sa.Halen
	for i := 0; i < len(sa.Addr); i++ {
		sa.raw.Addr[i] = sa.Addr[i]
	}
	return unsafe.Pointer(&sa.raw), SizeofSockaddrLinklayer, nil
}

// SockaddrVM implements the Sockaddr interface for AF_VSOCK type sockets.
// SockaddrVM provides access to Linux VM sockets: a mechanism that enables
// bidirectional communication between a hypervisor and its guest virtual
// machines.
type SockaddrVM struct {
	// CID and Port specify a context ID and port address for a VM socket.
	// Guests have a unique CID, and hosts may have a well-known CID of:
	//  - VMADDR_CID_HYPERVISOR: refers to the hypervisor process.
	//  - VMADDR_CID_HOST: refers to other processes on the host.
	CID  uint32
	Port uint32
	raw  RawSockaddrVM
}

func (sa *SockaddrVM) sockaddr() (unsafe.Pointer, _Socklen, error) {
	sa.raw.Family = AF_VSOCK
	sa.raw.Port = sa.Port
	sa.raw.Cid = sa.CID

	return unsafe.Pointer(&sa.raw), SizeofSockaddrVM, nil
}

// SockaddrNetlink implements the Sockaddr interface for AF_NETLINK type sockets.
type SockaddrNetlink struct {
	Family uint16
	Pad    uint16
	Pid    uint32
	Groups uint32
	raw    RawSockaddrNetlink
}

func (sa *SockaddrNetlink) sockaddr() (unsafe.Pointer, _Socklen, error) {
	sa.raw.Family = AF_NETLINK
	sa.raw.Pad = sa.Pad
	sa.raw.Pid = sa.Pid
	sa.raw.Groups = sa.Groups
	return unsafe.Pointer(&sa.raw), SizeofSockaddrNetlink, nil
}

func anyToSockaddr(fd int, rsa *RawSockaddrAny) (Sockaddr, error) {
	switch rsa.Addr.Family {
	case AF_NETLINK:
		pp := (*RawSockaddrNetlink)(unsafe.Pointer(rsa))
		sa := new(SockaddrNetlink)
		sa.Family = pp.Family
		sa.Pad = pp.Pad
		sa.Pid = pp.Pid
		sa.Groups = pp.Groups
		return sa, nil

	case AF_PACKET:
		pp := (*RawSockaddrLinklayer)(unsafe.Pointer(rsa))
		sa := new(SockaddrLinklayer)
		sa.Protocol = pp.Protocol
		sa.Ifindex = int(pp.Ifindex)
		sa.Hatype = pp.Hatype
		sa.Pkttype = pp.Pkttype
		sa.Halen = pp.Halen
		for i := 0; i < len(sa.Addr); i++ {
			sa.Addr[i] = pp.Addr[i]
		}
		return sa, nil

	case AF_UNIX:
		pp := (*RawSockaddrUnix)(unsafe.Pointer(rsa))
		sa := new(SockaddrUnix)
		if pp.Path[0] == 0 {
			// "Abstract" Unix domain socket.
			// Rewrite leading NUL as @ for textual display.
			// (This is the standard convention.)
			// Not friendly to overwrite in place,
			// but the callers below don't care.
			pp.Path[0] = '@'
		}

		// Assume path ends at NUL.
		// This is not technically the Linux semantics for
		// abstract Unix domain sockets--they are supposed
		// to be uninterpreted fixed-size binary blobs--but
		// everyone uses this convention.
		n := 0
		for n < len(pp.Path) && pp.Path[n] != 0 {
			n++
		}
		bytes := (*[len(pp.Path)]byte)(unsafe.Pointer(&pp.Path[0]))[0:n]
		sa.Name = string(bytes)
		return sa, nil

	case AF_INET:
		pp := (*RawSockaddrInet4)(unsafe.Pointer(rsa))
		sa := new(SockaddrInet4)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		for i := 0; i < len(sa.Addr); i++ {
			sa.Addr[i] = pp.Addr[i]
		}
		return sa, nil

	case AF_INET6:
		pp := (*RawSockaddrInet6)(unsafe.Pointer(rsa))
		sa := new(SockaddrInet6)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		sa.ZoneId = pp.Scope_id
		for i := 0; i < len(sa.Addr); i++ {
			sa.Addr[i] = pp.Addr[i]
		}
		return sa, nil

	case AF_VSOCK:
		pp := (*RawSockaddrVM)(unsafe.Pointer(rsa))
		sa := &SockaddrVM{
			CID:  pp.Cid,
			Port: pp.Port,
		}
		return sa, nil
	case AF_BLUETOOTH:
		proto, err := GetsockoptInt(fd, SOL_SOCKET, SO_PROTOCOL)
		if err != nil {
			return nil, err
		}
		// only BTPROTO_L2CAP and BTPROTO_RFCOMM can accept connections
		switch proto {
		case BTPROTO_L2CAP:
			pp := (*RawSockaddrL2)(unsafe.Pointer(rsa))
			sa := &SockaddrL2{
				PSM:      pp.Psm,
				CID:      pp.Cid,
				Addr:     pp.Bdaddr,
				AddrType: pp.Bdaddr_type,
			}
			return sa, nil
		case BTPROTO_RFCOMM:
			pp := (*RawSockaddrRFCOMM)(unsafe.Pointer(rsa))
			sa := &SockaddrRFCOMM{
				Channel: pp.Channel,
				Addr:    pp.Bdaddr,
			}
			return sa, nil
		}
	case AF_XDP:
		pp := (*RawSockaddrXDP)(unsafe.Pointer(rsa))
		sa := &SockaddrXDP{
			Flags:        pp.Flags,
			Ifindex:      pp.Ifindex,
			QueueID:      pp.Queue_id,
			SharedUmemFD: pp.Shared_umem_fd,
		}
		return sa, nil
	case AF_PPPOX:
		pp := (*RawSockaddrPPPoX)(unsafe.Pointer(rsa))
		if binary.BigEndian.Uint32(pp[2:6]) != px_proto_oe {
			return nil, EINVAL
		}
		sa := &SockaddrPPPoE{
			SID:    binary.BigEndian.Uint16(pp[6:8]),
			Remote: pp[8:14],
		}
		for i := 14; i < 14+IFNAMSIZ; i++ {
			if pp[i] == 0 {
				sa.Dev = string(pp[14:i])
				break
			}
		}
		return sa, nil
	case AF_TIPC:
		pp := (*RawSockaddrTIPC)(unsafe.Pointer(rsa))

		sa := &SockaddrTIPC{
			Scope: int(pp.Scope),
		}

		// Determine which union variant is present in pp.Addr by checking
		// pp.Addrtype.
		switch pp.Addrtype {
		case TIPC_SERVICE_RANGE:
			sa.Addr = (*TIPCServiceRange)(unsafe.Pointer(&pp.Addr))
		case TIPC_SERVICE_ADDR:
			sa.Addr = (*TIPCServiceName)(unsafe.Pointer(&pp.Addr))
		case TIPC_SOCKET_ADDR:
			sa.Addr = (*TIPCSocketAddr)(unsafe.Pointer(&pp.Addr))
		default:
			return nil, EINVAL
		}

		return sa, nil
	}
	return nil, EAFNOSUPPORT
}

// Sockaddr represents a socket address.
type Sockaddr interface {
	sockaddr() (ptr unsafe.Pointer, len _Socklen, err error) // lowercase; only we can define Sockaddrs
}

// SockaddrInet4 implements the Sockaddr interface for AF_INET type sockets.
type SockaddrInet4 struct {
	Port int
	Addr [4]byte
	raw  RawSockaddrInet4
}

// SockaddrInet6 implements the Sockaddr interface for AF_INET6 type sockets.
type SockaddrInet6 struct {
	Port   int
	ZoneId uint32
	Addr   [16]byte
	raw    RawSockaddrInet6
}

// SockaddrUnix implements the Sockaddr interface for AF_UNIX type sockets.
type SockaddrUnix struct {
	Name string
	raw  RawSockaddrUnix
}

func (sa *SockaddrUnix) sockaddr() (unsafe.Pointer, _Socklen, error) {
	name := sa.Name
	n := len(name)
	if n >= len(sa.raw.Path) {
		return nil, 0, EINVAL
	}
	sa.raw.Family = AF_UNIX
	for i := 0; i < n; i++ {
		sa.raw.Path[i] = int8(name[i])
	}
	// length is family (uint16), name, NUL.
	sl := _Socklen(2)
	if n > 0 {
		sl += _Socklen(n) + 1
	}
	if sa.raw.Path[0] == '@' {
		sa.raw.Path[0] = 0
		// Don't count trailing NUL for abstract address.
		sl--
	}

	return unsafe.Pointer(&sa.raw), sl, nil
}

func (sa *SockaddrInet4) sockaddr() (unsafe.Pointer, _Socklen, error) {
	if sa.Port < 0 || sa.Port > 0xFFFF {
		return nil, 0, EINVAL
	}
	sa.raw.Family = AF_INET
	p := (*[2]byte)(unsafe.Pointer(&sa.raw.Port))
	p[0] = byte(sa.Port >> 8)
	p[1] = byte(sa.Port)
	for i := 0; i < len(sa.Addr); i++ {
		sa.raw.Addr[i] = sa.Addr[i]
	}
	return unsafe.Pointer(&sa.raw), SizeofSockaddrInet4, nil
}

func (sa *SockaddrInet6) sockaddr() (unsafe.Pointer, _Socklen, error) {
	if sa.Port < 0 || sa.Port > 0xFFFF {
		return nil, 0, EINVAL
	}
	sa.raw.Family = AF_INET6
	p := (*[2]byte)(unsafe.Pointer(&sa.raw.Port))
	p[0] = byte(sa.Port >> 8)
	p[1] = byte(sa.Port)
	sa.raw.Scope_id = sa.ZoneId
	for i := 0; i < len(sa.Addr); i++ {
		sa.raw.Addr[i] = sa.Addr[i]
	}
	return unsafe.Pointer(&sa.raw), SizeofSockaddrInet6, nil
}

// SockaddrL2 implements the Sockaddr interface for AF_BLUETOOTH type sockets
// using the L2CAP protocol.
type SockaddrL2 struct {
	PSM      uint16
	CID      uint16
	Addr     [6]uint8
	AddrType uint8
	raw      RawSockaddrL2
}

func (sa *SockaddrL2) sockaddr() (unsafe.Pointer, _Socklen, error) {
	sa.raw.Family = AF_BLUETOOTH
	psm := (*[2]byte)(unsafe.Pointer(&sa.raw.Psm))
	psm[0] = byte(sa.PSM)
	psm[1] = byte(sa.PSM >> 8)
	for i := 0; i < len(sa.Addr); i++ {
		sa.raw.Bdaddr[i] = sa.Addr[len(sa.Addr)-1-i]
	}
	cid := (*[2]byte)(unsafe.Pointer(&sa.raw.Cid))
	cid[0] = byte(sa.CID)
	cid[1] = byte(sa.CID >> 8)
	sa.raw.Bdaddr_type = sa.AddrType
	return unsafe.Pointer(&sa.raw), SizeofSockaddrL2, nil
}

// SockaddrRFCOMM implements the Sockaddr interface for AF_BLUETOOTH type sockets
// using the RFCOMM protocol.
//
// Server example:
//
//      fd, _ := Socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM)
//      _ = unix.Bind(fd, &unix.SockaddrRFCOMM{
//      	Channel: 1,
//      	Addr:    [6]uint8{0, 0, 0, 0, 0, 0}, // BDADDR_ANY or 00:00:00:00:00:00
//      })
//      _ = Listen(fd, 1)
//      nfd, sa, _ := Accept(fd)
//      fmt.Printf("conn addr=%v fd=%d", sa.(*unix.SockaddrRFCOMM).Addr, nfd)
//      Read(nfd, buf)
//
// Client example:
//
//      fd, _ := Socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM)
//      _ = Connect(fd, &SockaddrRFCOMM{
//      	Channel: 1,
//      	Addr:    [6]byte{0x11, 0x22, 0x33, 0xaa, 0xbb, 0xcc}, // CC:BB:AA:33:22:11
//      })
//      Write(fd, []byte(`hello`))
type SockaddrRFCOMM struct {
	// Addr represents a bluetooth address, byte ordering is little-endian.
	Addr [6]uint8

	// Channel is a designated bluetooth channel, only 1-30 are available for use.
	// Since Linux 2.6.7 and further zero value is the first available channel.
	Channel uint8

	raw RawSockaddrRFCOMM
}

func (sa *SockaddrRFCOMM) sockaddr() (unsafe.Pointer, _Socklen, error) {
	sa.raw.Family = AF_BLUETOOTH
	sa.raw.Channel = sa.Channel
	sa.raw.Bdaddr = sa.Addr
	return unsafe.Pointer(&sa.raw), SizeofSockaddrRFCOMM, nil
}

// SockaddrCAN implements the Sockaddr interface for AF_CAN type sockets.
// The RxID and TxID fields are used for transport protocol addressing in
// (CAN_TP16, CAN_TP20, CAN_MCNET, and CAN_ISOTP), they can be left with
// zero values for CAN_RAW and CAN_BCM sockets as they have no meaning.
//
// The SockaddrCAN struct must be bound to the socket file descriptor
// using Bind before the CAN socket can be used.
//
//      // Read one raw CAN frame
//      fd, _ := Socket(AF_CAN, SOCK_RAW, CAN_RAW)
//      addr := &SockaddrCAN{Ifindex: index}
//      Bind(fd, addr)
//      frame := make([]byte, 16)
//      Read(fd, frame)
//
// The full SocketCAN documentation can be found in the linux kernel
// archives at: https://www.kernel.org/doc/Documentation/networking/can.txt
type SockaddrCAN struct {
	Ifindex int
	RxID    uint32
	TxID    uint32
	raw     RawSockaddrCAN
}

func (sa *SockaddrCAN) sockaddr() (unsafe.Pointer, _Socklen, error) {
	if sa.Ifindex < 0 || sa.Ifindex > 0x7fffffff {
		return nil, 0, EINVAL
	}
	sa.raw.Family = AF_CAN
	sa.raw.Ifindex = int32(sa.Ifindex)
	rx := (*[4]byte)(unsafe.Pointer(&sa.RxID))
	for i := 0; i < 4; i++ {
		sa.raw.Addr[i] = rx[i]
	}
	tx := (*[4]byte)(unsafe.Pointer(&sa.TxID))
	for i := 0; i < 4; i++ {
		sa.raw.Addr[i+4] = tx[i]
	}
	return unsafe.Pointer(&sa.raw), SizeofSockaddrCAN, nil
}

// SockaddrALG implements the Sockaddr interface for AF_ALG type sockets.
// SockaddrALG enables userspace access to the Linux kernel's cryptography
// subsystem. The Type and Name fields specify which type of hash or cipher
// should be used with a given socket.
//
// To create a file descriptor that provides access to a hash or cipher, both
// Bind and Accept must be used. Once the setup process is complete, input
// data can be written to the socket, processed by the kernel, and then read
// back as hash output or ciphertext.
//
// Here is an example of using an AF_ALG socket with SHA1 hashing.
// The initial socket setup process is as follows:
//
//      // Open a socket to perform SHA1 hashing.
//      fd, _ := unix.Socket(unix.AF_ALG, unix.SOCK_SEQPACKET, 0)
//      addr := &unix.SockaddrALG{Type: "hash", Name: "sha1"}
//      unix.Bind(fd, addr)
//      // Note: unix.Accept does not work at this time; must invoke accept()
//      // manually using unix.Syscall.
//      hashfd, _, _ := unix.Syscall(unix.SYS_ACCEPT, uintptr(fd), 0, 0)
//
// Once a file descriptor has been returned from Accept, it may be used to
// perform SHA1 hashing. The descriptor is not safe for concurrent use, but
// may be re-used repeatedly with subsequent Write and Read operations.
//
// When hashing a small byte slice or string, a single Write and Read may
// be used:
//
//      // Assume hashfd is already configured using the setup process.
//      hash := os.NewFile(hashfd, "sha1")
//      // Hash an input string and read the results. Each Write discards
//      // previous hash state. Read always reads the current state.
//      b := make([]byte, 20)
//      for i := 0; i < 2; i++ {
//          io.WriteString(hash, "Hello, world.")
//          hash.Read(b)
//          fmt.Println(hex.EncodeToString(b))
//      }
//      // Output:
//      // 2ae01472317d1935a84797ec1983ae243fc6aa28
//      // 2ae01472317d1935a84797ec1983ae243fc6aa28
//
// For hashing larger byte slices, or byte streams such as those read from
// a file or socket, use Sendto with MSG_MORE to instruct the kernel to update
// the hash digest instead of creating a new one for a given chunk and finalizing it.
//
//      // Assume hashfd and addr are already configured using the setup process.
//      hash := os.NewFile(hashfd, "sha1")
//      // Hash the contents of a file.
//      f, _ := os.Open("/tmp/linux-4.10-rc7.tar.xz")
//      b := make([]byte, 4096)
//      for {
//          n, err := f.Read(b)
//          if err == io.EOF {
//              break
//          }
//          unix.Sendto(hashfd, b[:n], unix.MSG_MORE, addr)
//      }
//      hash.Read(b)
//      fmt.Println(hex.EncodeToString(b))
//      // Output: 85cdcad0c06eef66f805ecce353bec9accbeecc5
//
// For more information, see: http://www.chronox.de/crypto-API/crypto/userspace-if.html.
type SockaddrALG struct {
	Type    string
	Name    string
	Feature uint32
	Mask    uint32
	raw     RawSockaddrALG
}

func (sa *SockaddrALG) sockaddr() (unsafe.Pointer, _Socklen, error) {
	// Leave room for NUL byte terminator.
	if len(sa.Type) > 13 {
		return nil, 0, EINVAL
	}
	if len(sa.Name) > 63 {
		return nil, 0, EINVAL
	}

	sa.raw.Family = AF_ALG
	sa.raw.Feat = sa.Feature
	sa.raw.Mask = sa.Mask

	typ, err := ByteSliceFromString(sa.Type)
	if err != nil {
		return nil, 0, err
	}
	name, err := ByteSliceFromString(sa.Name)
	if err != nil {
		return nil, 0, err
	}

	copy(sa.raw.Type[:], typ)
	copy(sa.raw.Name[:], name)

	return unsafe.Pointer(&sa.raw), SizeofSockaddrALG, nil
}


type SockaddrXDP struct {
	Flags        uint16
	Ifindex      uint32
	QueueID      uint32
	SharedUmemFD uint32
	raw          RawSockaddrXDP
}

func (sa *SockaddrXDP) sockaddr() (unsafe.Pointer, _Socklen, error) {
	sa.raw.Family = AF_XDP
	sa.raw.Flags = sa.Flags
	sa.raw.Ifindex = sa.Ifindex
	sa.raw.Queue_id = sa.QueueID
	sa.raw.Shared_umem_fd = sa.SharedUmemFD

	return unsafe.Pointer(&sa.raw), SizeofSockaddrXDP, nil
}

// This constant mirrors the #define of PX_PROTO_OE in
// linux/if_pppox.h. We're defining this by hand here instead of
// autogenerating through mkerrors.sh because including
// linux/if_pppox.h causes some declaration conflicts with other
// includes (linux/if_pppox.h includes linux/in.h, which conflicts
// with netinet/in.h). Given that we only need a single zero constant
// out of that file, it's cleaner to just define it by hand here.
const px_proto_oe = 0

type SockaddrPPPoE struct {
	SID    uint16
	Remote []byte
	Dev    string
	raw    RawSockaddrPPPoX
}

func (sa *SockaddrPPPoE) sockaddr() (unsafe.Pointer, _Socklen, error) {
	if len(sa.Remote) != 6 {
		return nil, 0, EINVAL
	}
	if len(sa.Dev) > IFNAMSIZ-1 {
		return nil, 0, EINVAL
	}

	*(*uint16)(unsafe.Pointer(&sa.raw[0])) = AF_PPPOX
	// This next field is in host-endian byte order. We can't use the
	// same unsafe pointer cast as above, because this value is not
	// 32-bit aligned and some architectures don't allow unaligned
	// access.
	//
	// However, the value of px_proto_oe is 0, so we can use
	// encoding/binary helpers to write the bytes without worrying
	// about the ordering.
	binary.BigEndian.PutUint32(sa.raw[2:6], px_proto_oe)
	// This field is deliberately big-endian, unlike the previous
	// one. The kernel expects SID to be in network byte order.
	binary.BigEndian.PutUint16(sa.raw[6:8], sa.SID)
	copy(sa.raw[8:14], sa.Remote)
	for i := 14; i < 14+IFNAMSIZ; i++ {
		sa.raw[i] = 0
	}
	copy(sa.raw[14:], sa.Dev)
	return unsafe.Pointer(&sa.raw), SizeofSockaddrPPPoX, nil
}

// SockaddrTIPC implements the Sockaddr interface for AF_TIPC type sockets.
// For more information on TIPC, see: http://tipc.sourceforge.net/.
type SockaddrTIPC struct {
	// Scope is the publication scopes when binding service/service range.
	// Should be set to TIPC_CLUSTER_SCOPE or TIPC_NODE_SCOPE.
	Scope int

	// Addr is the type of address used to manipulate a socket. Addr must be
	// one of:
	//  - *TIPCSocketAddr: "id" variant in the C addr union
	//  - *TIPCServiceRange: "nameseq" variant in the C addr union
	//  - *TIPCServiceName: "name" variant in the C addr union
	//
	// If nil, EINVAL will be returned when the structure is used.
	Addr TIPCAddr

	raw RawSockaddrTIPC
}

// TIPCAddr is implemented by types that can be used as an address for
// SockaddrTIPC. It is only implemented by *TIPCSocketAddr, *TIPCServiceRange,
// and *TIPCServiceName.
type TIPCAddr interface {
	tipcAddrtype() uint8
	tipcAddr() [12]byte
}

func (sa *TIPCSocketAddr) tipcAddr() [12]byte {
	var out [12]byte
	copy(out[:], (*(*[unsafe.Sizeof(TIPCSocketAddr{})]byte)(unsafe.Pointer(sa)))[:])
	return out
}

func (sa *TIPCSocketAddr) tipcAddrtype() uint8 { return TIPC_SOCKET_ADDR }

func (sa *TIPCServiceRange) tipcAddr() [12]byte {
	var out [12]byte
	copy(out[:], (*(*[unsafe.Sizeof(TIPCServiceRange{})]byte)(unsafe.Pointer(sa)))[:])
	return out
}

func (sa *TIPCServiceRange) tipcAddrtype() uint8 { return TIPC_SERVICE_RANGE }

func (sa *TIPCServiceName) tipcAddr() [12]byte {
	var out [12]byte
	copy(out[:], (*(*[unsafe.Sizeof(TIPCServiceName{})]byte)(unsafe.Pointer(sa)))[:])
	return out
}

func (sa *TIPCServiceName) tipcAddrtype() uint8 { return TIPC_SERVICE_ADDR }

func (sa *SockaddrTIPC) sockaddr() (unsafe.Pointer, _Socklen, error) {
	if sa.Addr == nil {
		return nil, 0, EINVAL
	}

	sa.raw.Family = AF_TIPC
	sa.raw.Scope = int8(sa.Scope)
	sa.raw.Addrtype = sa.Addr.tipcAddrtype()
	sa.raw.Addr = sa.Addr.tipcAddr()

	return unsafe.Pointer(&sa.raw), SizeofSockaddrTIPC, nil
}

type WaitStatus uint32

// Wait status is 7 bits at bottom, either 0 (exited),
// 0x7F (stopped), or a signal number that caused an exit.
// The 0x80 bit is whether there was a core dump.
// An extra number (exit code, signal causing a stop)
// is in the high bits. At least that's the idea.
// There are various irregularities. For example, the
// "continued" status is 0xFFFF, distinguishing itself
// from stopped via the core dump bit.

const (
	mask    = 0x7F
	core    = 0x80
	exited  = 0x00
	stopped = 0x7F
	shift   = 8
)

func (w WaitStatus) Exited() bool { return w&mask == exited }

func (w WaitStatus) Signaled() bool { return w&mask != stopped && w&mask != exited }

func (w WaitStatus) Stopped() bool { return w&0xFF == stopped }

func (w WaitStatus) Continued() bool { return w == 0xFFFF }

func (w WaitStatus) CoreDump() bool { return w.Signaled() && w&core != 0 }

func (w WaitStatus) ExitStatus() int {
	if !w.Exited() {
		return -1
	}
	return int(w>>shift) & 0xFF
}

func (w WaitStatus) Signal() syscall.Signal {
	if !w.Signaled() {
		return -1
	}
	return syscall.Signal(w & mask)
}

func (w WaitStatus) StopSignal() syscall.Signal {
	if !w.Stopped() {
		return -1
	}
	return syscall.Signal(w>>shift) & 0xFF
}

func (w WaitStatus) TrapCause() int {
	if w.StopSignal() != SIGTRAP {
		return -1
	}
	return int(w>>shift) >> 8
}

//sys	Fstatfs(fd int, buf *Statfs_t) (err error)
//fstatfs64(fd _C_int, buf *Statfs_t) _C_int
func CloseOnExec(fd int) { fcntl(fd, F_SETFD, FD_CLOEXEC) }

// Automatically generated wrapper for socketpair/socketpair
//extern socketpair
func c_socketpair(domain _C_int, typ _C_int, protocol _C_int, fd *[2]_C_int) _C_int
func socketpair(domain int, typ int, proto int, fd *[2]_C_int) (err error) {
	_r := c_socketpair(_C_int(domain), _C_int(typ), _C_int(proto), fd)
	var errno syscall.Errno
	setErrno := false
	if _r < 0 {
		errno = syscall.GetErrno()
		setErrno = true
	}
	if setErrno {
		err = errno
	}
	return
}

func Socketpair(domain, typ, proto int) (fd [2]int, err error) {
	var fdx [2]_C_int
	err = socketpair(domain, typ, proto, &fdx)
	if err == nil {
		fd[0] = int(fdx[0])
		fd[1] = int(fdx[1])
	}
	return
}

// Automatically generated wrapper for raw_fcntl/__go_fcntl
//extern __go_fcntl
func c___go_fcntl(fd _C_int, cmd _C_int, arg _C_int) _C_int

// Automatically generated wrapper for fcntl/__go_fcntl
func fcntl(fd int, cmd int, arg int) (val int, err error) {
	syscall.Entersyscall()
	_r := c___go_fcntl(_C_int(fd), _C_int(cmd), _C_int(arg))
	val = (int)(_r)
	var errno syscall.Errno
	setErrno := false
	if _r < 0 {
		errno = syscall.GetErrno()
		setErrno = true
	}
	syscall.Exitsyscall()
	if setErrno {
		err = errno
	}
	return
}

// taken from libgo sysinfo.go
type _fsid_t struct { val [1+1]int32; }
type _statfs struct { f_version uint32; f_type uint32; f_flags uint64; f_bsize uint64; f_iosize uint64; f_blocks uint64; f_bfree uint64; f_bavail int64; f_files uint64; f_ffree int64; f_syncwrites uint64; f_asyncwrites uint64; f_syncreads uint64; f_asyncreads uint64; f_spare [9+1]uint64; f_namemax uint32; f_owner uint32; f_fsid _fsid_t; f_charspare [79+1]int8; f_fstypename [15+1]int8; f_mntfromname [1023+1]int8; f_mntonname [1023+1]int8; }

// wrapper
//extern fstatfs
func c_fstatfs (int32, *Statfs_t) int32
func Fstatfs(fd int, buf *Statfs_t) (err error) {
	_r := c_fstatfs(int32(fd), buf)
	var errno syscall.Errno
	setErrno := false
	if _r < 0 {
		errno = syscall.GetErrno()
		setErrno = true
	}
	if setErrno {
		err = errno
	}
	return
}

//extern kill
func c_kill(pid syscall.Pid_t, sig _C_int) _C_int
// Automatically generated wrapper for Kill/kill
func Kill(pid int, sig Signal) (err error) {
	_r := c_kill(syscall.Pid_t(pid), _C_int(sig))
	var errno syscall.Errno
	setErrno := false
	if _r < 0 {
		errno = syscall.GetErrno()
		setErrno = true
	}
	if setErrno {
		err = errno
	}
	return
}

// Automatically generated wrapper for Umask/umask
//extern umask
func c_umask(mask syscall.Mode_t) syscall.Mode_t
func Umask(mask int) (oldmask int) {
	_r := c_umask(syscall.Mode_t(mask))
	oldmask = (int)(_r)
	return
}

func EpollCreate1(flag int) (fd int, err error) {
	println("EpollCreate1 not implemented!")
	return 0, nil
}

// dummy implementation for github.com/fsnotify/fsnotify/inotify.go
//sys	InotifyAddWatch(fd int, pathname string, mask uint32) (watchdesc int, err error)
//inotify_add_watch(fd _C_int, pathname *byte, mask uint32) _C_int
func InotifyAddWatch(fd int, pathname string, mask uint32) (watchdesc int, err error) {
	println("InotifyAddWatch not implemented!")
	return 0, nil
}

//sysnb	InotifyInit() (fd int, err error)
//inotify_init() _C_int

//sysnb	InotifyInit1(flags int) (fd int, err error)
//inotify_init1(flags _C_int) _C_int
func InotifyInit1(flags int) (fd int, err error) {
	println("InotifyInit1 not implemented!")
	return 0, nil
}

//sysnb	InotifyRmWatch(fd int, watchdesc uint32) (success int, err error)
//inotify_rm_watch(fd _C_int, wd uint32) _C_int
func InotifyRmWatch(fd int, watchdesc uint32) (success int, err error) {
	println("InotifyRmWatch not implemented!")
	return 0, nil
}

// Automatically generated wrapper for Close/close
//extern close
func c_close(fd _C_int) _C_int
func Close(fd int) (err error) {
	syscall.Entersyscall()
	_r := c_close(_C_int(fd))
	var errno syscall.Errno
	setErrno := false
	if _r < 0 {
		errno = syscall.GetErrno()
		setErrno = true
	}
	syscall.Exitsyscall()
	if setErrno {
		err = errno
	}
	return
}

// Automatically generated wrapper for read/read
//extern read
func c_read(fd _C_int, buf *byte, count syscall.Size_t) syscall.Ssize_t
func Read(fd int, p []byte) (n int, err error) {
	var _p2 *byte
	if len(p) > 0 {
		_p2 = (*byte)(unsafe.Pointer(&p[0]))
	} else {
		_p2 = (*byte)(unsafe.Pointer(&_zero))
	}
	syscall.Entersyscall()
	_r := c_read(_C_int(fd), _p2, syscall.Size_t(len(p)))
	n = (int)(_r)
	var errno syscall.Errno
	setErrno := false
	if _r < 0 {
		errno = syscall.GetErrno()
		setErrno = true
	}
	syscall.Exitsyscall()
	if setErrno {
		err = errno
	}
	return
}

//sysnb pipe2(p *[2]_C_int, flags int) (err error)

func Pipe2(p []int, flags int) (err error) {
	println("Pipe2 not implemented!")
	return nil
}

//sysnb	EpollCtl(epfd int, op int, fd int, event *EpollEvent) (err error)
//epoll_ctl(epfd _C_int, op _C_int, fd _C_int, event *EpollEvent) _C_int
func EpollCtl(epfd int, op int, fd int, event *EpollEvent) (err error) {
	println("EpollCtl not implemented!")
	return nil
}

//sys	EpollWait(epfd int, events []EpollEvent, msec int) (n int, err error)
//epoll_wait(epfd _C_int, events *EpollEvent, maxevents _C_int, timeout _C_int) _C_int
func EpollWait(epfd int, events []EpollEvent, msec int) (n int, err error) {
	println("EpollWait not implemented!")
	return 0,nil
}

//extern write
func c_write(fd _C_int, buf *byte, count syscall.Size_t) syscall.Ssize_t
func Write(fd int, p []byte) (n int, err error) {
	var _p2 *byte
	if len(p) > 0 {
		_p2 = (*byte)(unsafe.Pointer(&p[0]))
	} else {
		_p2 = (*byte)(unsafe.Pointer(&_zero))
	}
	syscall.Entersyscall()
	_r := c_write(_C_int(fd), _p2, syscall.Size_t(len(p)))
	n = (int)(_r)
	var errno syscall.Errno
	setErrno := false
	if _r < 0 {
		errno = syscall.GetErrno()
		setErrno = true
	}
	syscall.Exitsyscall()
	if setErrno {
		err = errno
	}
	return
}

func Mknod(path string, mode uint32, dev int) (err error) {
	return syscall.Mknod(path, mode, dev)
}

//sys	fchmodat(dirfd int, path string, mode uint32) (err error)

func Fchmodat(dirfd int, path string, mode uint32, flags int) (err error) {
	println("Fchmodat not implemented!")
	return nil
}

// Automatically generated wrapper for Lstat/lstat
//extern lstat
func c_lstat(path *byte, stat *Stat_t) _C_int
func Lstat(path string, stat *Stat_t) (err error) {
	var _p1 *byte
	_p1, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	syscall.Entersyscall()
	_r := c_lstat(_p1, stat)
	var errno syscall.Errno
	setErrno := false
	if _r < 0 {
		errno = syscall.GetErrno()
		setErrno = true
	}
	syscall.Exitsyscall()
	if setErrno {
		err = errno
	}
	return
}

// Automatically generated wrapper for raw_chroot/chroot
//extern chroot
func c_chroot(path *byte) _C_int
func Chroot(path string) (err error) {
	var _p1 *byte
	_p1, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	syscall.Entersyscall()
	_r := c_chroot(_p1)
	var errno syscall.Errno
	setErrno := false
	if _r < 0 {
		errno = syscall.GetErrno()
		setErrno = true
	}
	syscall.Exitsyscall()
	if setErrno {
		err = errno
	}
	return
}

// Automatically generated wrapper for raw_chdir/chdir
//extern chdir
func c_chdir(path *byte) _C_int
func Chdir(path string) (err error) {
	var _p1 *byte
	_p1, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	syscall.Entersyscall()
	_r := c_chdir(_p1)
	var errno syscall.Errno
	setErrno := false
	if _r < 0 {
		errno = syscall.GetErrno()
		setErrno = true
	}
	syscall.Exitsyscall()
	if setErrno {
		err = errno
	}
	return
}
// Automatically generated wrapper for Unlink/unlink
//extern unlink
func c_unlink(path *byte) _C_int
func Unlink(path string) (err error) {
	var _p1 *byte
	_p1, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	syscall.Entersyscall()
	_r := c_unlink(_p1)
	var errno syscall.Errno
	setErrno := false
	if _r < 0 {
		errno = syscall.GetErrno()
		setErrno = true
	}
	syscall.Exitsyscall()
	if setErrno {
		err = errno
	}
	return
}

// Automatically generated wrapper for raw_ioctl_ptr/__go_ioctl_ptr
//go:noescape
//extern __go_ioctl_ptr
func c___go_ioctl_ptr(fd _C_int, cmd _C_int, val unsafe.Pointer) _C_int
func ioctl(fd int, req uint, arg uintptr) (err error) {
	syscall.Entersyscall()
	_r := c___go_ioctl_ptr(_C_int(fd), _C_int(req), unsafe.Pointer(arg))
	var errno syscall.Errno
	setErrno := false
	if _r < 0 {
		errno = syscall.GetErrno()
		setErrno = true
	}
	syscall.Exitsyscall()
	if setErrno {
		err = error(errno)
	}
	return
}

// A Signal is a number describing a process signal.
// It implements the os.Signal interface.
// type Signal int

func Mkfifo(path string, mode uint32) (err error) {
	return syscall.Mkfifo(path, mode)
}

// type SysProcAttr = syscall.SysProcAttr


// Automatically generated wrapper for Fchown/fchown
//go:noescape
//extern fchown
func c_fchown(fd _C_int, uid Uid_t, gid Gid_t) _C_int
func Fchown(fd int, uid int, gid int) (err error) {
	syscall.Entersyscall()
	_r := c_fchown(_C_int(fd), Uid_t(uid), Gid_t(gid))
	var errno syscall.Errno
	setErrno := false
	if _r < 0 {
		errno = syscall.GetErrno()
		setErrno = true
	}
	syscall.Exitsyscall()
	if setErrno {
		err = errno
	}
	return
}

func Prctl(option int, arg2 uintptr, arg3 uintptr, arg4 uintptr, arg5 uintptr) (err error) {
	// _, _, e1 := Syscall6(SYS_PRCTL, uintptr(option), uintptr(arg2), uintptr(arg3), uintptr(arg4), uintptr(arg5), 0)
	// if e1 != 0 {
	// 	err = errnoErr(e1)
	// }
	println("Prctl not implemented!")
	return
}
