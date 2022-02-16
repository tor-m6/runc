// +build !linux

package nl

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/unix"
	"sync"
	"sync/atomic"
	// "syscall"
	"unsafe"
)

const (
	// Family type definitions
	FAMILY_ALL  = unix.AF_UNSPEC
	FAMILY_V4   = unix.AF_INET
	FAMILY_V6   = unix.AF_INET6
	FAMILY_MPLS = unix.AF_MPLS
	// Arbitrary set value (greater than default 4k) to allow receiving
	// from kernel more verbose messages e.g. for statistics,
	// tc rules or filters, or other more memory requiring data.
	RECEIVE_BUFFER_SIZE = 65536
	// Kernel netlink pid
	PidKernel uint32 = 0
)

var SupportedNlFamilies = []int{}
var nextSeqNr uint32

func NativeEndian() binary.ByteOrder {
	return nil
}

type NetlinkSocket struct {
	fd  int32
	lsa unix.SockaddrNetlink
	sync.Mutex
}

// SocketHandle contains the netlink socket and the associated
// sequence counter for a specific netlink family
type SocketHandle struct {
	Seq    uint32
	Socket *NetlinkSocket
}

type NetlinkRequest struct {
	unix.NlMsghdr
	Data    []NetlinkRequestData
	RawData []byte
	Sockets map[int]*SocketHandle
}

// Create a new netlink request from proto and flags
// Note the Len value will be inaccurate once data is added until
// the message is serialized
func NewNetlinkRequest(proto, flags int) *NetlinkRequest {
	return &NetlinkRequest{
		NlMsghdr: unix.NlMsghdr{
			Len:   uint32(unix.SizeofNlMsghdr),
			Type:  uint16(proto),
			Flags: unix.NLM_F_REQUEST | uint16(flags),
			Seq:   atomic.AddUint32(&nextSeqNr, 1),
		},
	}
}

type NetlinkRequestData interface {
	Len() int
	Serialize() []byte
}

// Serialize the Netlink Request into a byte array
func (req *NetlinkRequest) Serialize() []byte {
	length := unix.SizeofNlMsghdr
	dataBytes := make([][]byte, len(req.Data))
	for i, data := range req.Data {
		dataBytes[i] = data.Serialize()
		length = length + len(dataBytes[i])
	}
	length += len(req.RawData)

	req.Len = uint32(length)
	b := make([]byte, length)
	hdr := (*(*[unix.SizeofNlMsghdr]byte)(unsafe.Pointer(req)))[:]
	next := unix.SizeofNlMsghdr
	copy(b[0:next], hdr)
	for _, data := range dataBytes {
		for _, dataByte := range data {
			b[next] = dataByte
			next = next + 1
		}
	}
	// Add the raw data if any
	if len(req.RawData) > 0 {
		copy(b[next:length], req.RawData)
	}
	return b
}

func (req *NetlinkRequest) AddData(data NetlinkRequestData) {
	req.Data = append(req.Data, data)
}

// // IfInfomsg is related to links, but it is used for list requests as well
// type IfInfomsg struct {
// 	unix.IfInfomsg
// }

// func (msg *IfInfomsg) Serialize() []byte {
// 	return (*(*[unix.SizeofIfInfomsg]byte)(unsafe.Pointer(msg)))[:]
// }

// AddRawData adds raw bytes to the end of the NetlinkRequest object during serialization
func (req *NetlinkRequest) AddRawData(data []byte) {
	req.RawData = append(req.RawData, data...)
}

// Execute the request against a the given sockType.
// Returns a list of netlink messages in serialized format, optionally filtered
// by resType.
// func (req *NetlinkRequest) Execute(sockType int, resType uint16) ([][]byte, error) {
// 	var (
// 		s   *NetlinkSocket
// 		err error
// 	)

// 	if req.Sockets != nil {
// 		if sh, ok := req.Sockets[sockType]; ok {
// 			s = sh.Socket
// 			req.Seq = atomic.AddUint32(&sh.Seq, 1)
// 		}
// 	}
// 	sharedSocket := s != nil

// 	if s == nil {
// 		s, err = getNetlinkSocket(sockType)
// 		if err != nil {
// 			return nil, err
// 		}
// 		defer s.Close()
// 	} else {
// 		s.Lock()
// 		defer s.Unlock()
// 	}

// 	if err := s.Send(req); err != nil {
// 		return nil, err
// 	}

// 	pid, err := s.GetPid()
// 	if err != nil {
// 		return nil, err
// 	}

// 	var res [][]byte

// done:
// 	for {
// 		msgs, from, err := s.Receive()
// 		if err != nil {
// 			return nil, err
// 		}
// 		if from.Pid != PidKernel {
// 			return nil, fmt.Errorf("Wrong sender portid %d, expected %d", from.Pid, PidKernel)
// 		}
// 		for _, m := range msgs {
// 			if m.Header.Seq != req.Seq {
// 				if sharedSocket {
// 					continue
// 				}
// 				return nil, fmt.Errorf("Wrong Seq nr %d, expected %d", m.Header.Seq, req.Seq)
// 			}
// 			if m.Header.Pid != pid {
// 				continue
// 			}
// 			if m.Header.Type == unix.NLMSG_DONE {
// 				break done
// 			}
// 			if m.Header.Type == unix.NLMSG_ERROR {
// 				native := NativeEndian()
// 				error := int32(native.Uint32(m.Data[0:4]))
// 				if error == 0 {
// 					break done
// 				}
// 				return nil, syscall.Errno(-error)
// 			}
// 			if resType != 0 && m.Header.Type != resType {
// 				continue
// 			}
// 			res = append(res, m.Data)
// 			if m.Header.Flags&unix.NLM_F_MULTI == 0 {
// 				break done
// 			}
// 		}
// 	}
// 	return res, nil
// }

func (s *NetlinkSocket) Send(request *NetlinkRequest) error {
	fd := int(atomic.LoadInt32(&s.fd))
	if fd < 0 {
		return fmt.Errorf("Send called on a closed socket")
	}
	if err := unix.Sendto(fd, request.Serialize(), 0, &s.lsa); err != nil {
		return err
	}
	return nil
}


// func getNetlinkSocket(protocol int) (*NetlinkSocket, error) {
// 	fd, err := syscall.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, protocol)
// 	if err != nil {
// 		return nil, err
// 	}
// 	s := &NetlinkSocket{
// 		fd: int32(fd),
// 	}
// 	s.lsa.Family = unix.AF_NETLINK
// 	if err := syscall.Bind(fd, &s.lsa); err != nil {
// 		unix.Close(fd)
// 		return nil, err
// 	}

// 	return s, nil
// }

func (s *NetlinkSocket) GetPid() (uint32, error) {
	fd := int(atomic.LoadInt32(&s.fd))
	lsa, err := unix.Getsockname(fd)
	if err != nil {
		return 0, err
	}
	switch v := lsa.(type) {
	case *unix.SockaddrNetlink:
		return v.Pid, nil
	}
	return 0, fmt.Errorf("Wrong socket type")
}

func (s *NetlinkSocket) Receive() ([]unix.NetlinkMessage, *unix.SockaddrNetlink, error) {
	fd := int(atomic.LoadInt32(&s.fd))
	if fd < 0 {
		return nil, nil, fmt.Errorf("Receive called on a closed socket")
	}
	var fromAddr *unix.SockaddrNetlink
	var rb [RECEIVE_BUFFER_SIZE]byte
	nr, from, err := unix.Recvfrom(fd, rb[:], 0)
	if err != nil {
		return nil, nil, err
	}
	fromAddr, ok := from.(*unix.SockaddrNetlink)
	if !ok {
		return nil, nil, fmt.Errorf("Error converting to netlink sockaddr")
	}
	if nr < unix.NLMSG_HDRLEN {
		return nil, nil, fmt.Errorf("Got short response from netlink")
	}
	rb2 := make([]byte, nr)
	copy(rb2, rb[:nr])
	nl, err := unix.ParseNetlinkMessage(rb2)
	if err != nil {
		return nil, nil, err
	}
	return nl, fromAddr, nil
}

func (s *NetlinkSocket) Close() {
	fd := int(atomic.SwapInt32(&s.fd, -1))
	unix.Close(fd)
}

