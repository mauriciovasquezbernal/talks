// This program shows how to use the cilium/ebpf library to load a
// collection spec, load this into the kernel and attach and eBPF
// program to a tracepoint. The output of the eBPF program is printed to
// /sys/kernel/debug/tracing/trace_pipe.
// go run -exec sudo .
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

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load the collection spec (nothing is loaded into the kernel yet)
	spec, err := ebpf.LoadCollectionSpec("tracepoint1.bpf.o")
	if err != nil {
		log.Fatalf("Failed to load collection spec: %s", err)
	}

	//fmt.Printf("program spec is: %+v\n", spec.Programs["sys_enter_execve"])

	// We can modify here parameters of the spec before loading it into the kernel.

	// Load the spec into the kernel (create ebpf programs and maps)
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to load collection: %s", err)
	}
	defer coll.Close()

	//fmt.Printf("program is: %+v\n", coll.Programs["sys_enter_execve"])

	// Attach program to tracepoint
	kp, err := link.Tracepoint("syscalls", "sys_enter_execve", coll.Programs["sys_enter_execve"], nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kp.Close()

	fmt.Print("Ready, press Ctrl+C to close: ")

	// Graceful shutdown
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	<-exit
}
