// +build !linux

package nl

import (
	"encoding/binary"
	"golang.org/x/sys/unix"
	"sync"
	"sync/atomic"
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
