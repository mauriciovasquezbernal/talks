package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/florianl/go-tc"
	helper "github.com/florianl/go-tc/core"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf drop.bpf.c -- -I../headers

func uint32Ptr(v uint32) *uint32 {
	return &v
}

func stringPtr(v string) *string {
	return &v
}

// https://gist.github.com/ammario/649d4c0da650162efd404af23e25b86b
func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, nn)
	return ip
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.LittleEndian.Uint32(ip[12:16])
	}
	return binary.LittleEndian.Uint32(ip)
}

func fillMap(m *ebpf.Map, ips []string) error {
	zero := uint8(0)

	for _, ip := range ips {
		key := ip2int(net.ParseIP(ip))

		if err := m.Put(key, zero); err != nil {
			return err
		}
	}

	return nil
}

const (
	handleMajMask uint32 = 0xFFFF0000
	handleMinMask uint32 = 0x0000FFFF
)

func TC_H_MAKE(maj, min uint32) uint32 {
	return (((maj) & handleMajMask) | (min & handleMinMask))
}

// HostToNetShort converts a 16-bit integer from host to network byte order, aka "htons"
func HostToNetShort(i uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, i)
	return binary.BigEndian.Uint16(b)
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	if err := fillMap(objs.Ips, os.Args[2:]); err != nil {
		log.Fatalf("initializing ips map: %s", err)
	}

	info, _ := objs.IngressDrop.Info()

	// Setup tc socket for communication with the kernel
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open rtnetlink socket: %v\n", err)
		return
	}
	defer func() {
		if err := tcnl.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "could not close rtnetlink socket: %v\n", err)
		}
	}()

	// Attach ingress program
	qdiscIngress := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  helper.BuildHandle(0xFFFF, 0x0000),
			Parent:  tc.HandleIngress,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}

	// Install Qdisc on interface
	if err := tcnl.Qdisc().Add(&qdiscIngress); err != nil && !errors.Is(err, os.ErrExist) {
		fmt.Fprintf(os.Stderr, "could not assign clsact ingress to %s: %v\n", ifaceName, err)
		return
	}
	// when deleting the qdisc, the applied filter will also be gone
	defer tcnl.Qdisc().Delete(&qdiscIngress)

	filterIngress := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  0,
			Parent:  0xFFFFFFF2,
			Info:    0x10300,
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    uint32Ptr(uint32(objs.IngressDrop.FD())),
				Name:  stringPtr(info.Name),
				Flags: uint32Ptr(0x1),
			},
		},
	}
	if err := tcnl.Filter().Add(&filterIngress); err != nil && !errors.Is(err, os.ErrExist) {
		fmt.Fprintf(os.Stderr, "could not assign eBPF: %v\n", err)
		return
	}

	// Attach egress program
	qdiscEgress := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  helper.BuildHandle(0xFFFF, 0),
			Parent:  helper.BuildHandle(0xFFFF, 0xFFF1),
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}

	// Install Qdisc on interface
	if err := tcnl.Qdisc().Add(&qdiscEgress); err != nil && !errors.Is(err, os.ErrExist) {
		fmt.Fprintf(os.Stderr, "could not assign clsact to %s: %v\n", ifaceName, err)
		return
	}
	// when deleting the qdisc, the applied filter will also be gone
	defer tcnl.Qdisc().Delete(&qdiscEgress)

	filterEgress := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  1,
			Info:    TC_H_MAKE(1<<16, uint32(HostToNetShort(0x0003))),
			Parent:  TC_H_MAKE(0xFFFFFFF1, 0xFFF3),
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    uint32Ptr(uint32(objs.EgressDrop.FD())),
				Name:  stringPtr(info.Name),
				Flags: uint32Ptr(0x1),
			},
		},
	}

	if err := tcnl.Filter().Add(&filterEgress); err != nil && !errors.Is(err, os.ErrExist) {
		fmt.Fprintf(os.Stderr, "could not assign eBPF: %v\n", err)
		return
	}

	fmt.Print("Dropping packets. Press Ctrl+C to close: ")

	// Graceful shutdown
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	<-exit
}
