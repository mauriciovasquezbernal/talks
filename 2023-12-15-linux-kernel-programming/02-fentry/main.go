// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target=amd64 bpf fentry.bpf.c -- -I../headers

func main() {
	// Name of the kernel function to trace.
	//fn := "do_unlinkat"

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Attach to the relevant kernel function. Each time it enters, the program will print a
	// message to /sys/kernel/debug/tracing/trace_pipe
	lEntry, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.DoUnlinkat,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		log.Fatalf("attaching program: %s", err)
	}
	defer lEntry.Close()

	lExit, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.DoUnlinkatExit,
		AttachType: ebpf.AttachTraceFExit,
	})
	if err != nil {
		log.Fatalf("attaching program: %s", err)
	}
	defer lExit.Close()

	fmt.Print("Run sudo cat /sys/kernel/debug/tracing/trace_pipe in another terminal to see the output\n")
	fmt.Print("Press Ctrl+C to close: ")

	// Graceful shutdown
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	<-exit
}
