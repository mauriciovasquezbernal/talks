// This program demonstrates the use of a hashmap. It count the number
// of invocations to openat() per pid.
// go run -exec sudo .
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf tracepoint1.bpf.c

func main() {
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

	// Open a tracepoint and attach the pre-compiled program.
	kp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.SysEnterExecve, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kp.Close()

	fmt.Println("Ready, press Ctrl+C to close: ")

	// Graceful shutdown
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)

	// taken from https://github.com/cilium/ebpf/blob/master/examples/tracepoint_in_c/main.go
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

out:
	for {
		select {
		case <-ticker.C:
			var pid uint32
			var count uint32

			iterator := objs.Counter.Iterate()

			for iterator.Next(&pid, &count) {
				fmt.Printf("PID %d called openat() %d times\n", pid, count)
			}

			fmt.Println()
		case <-exit:
			break out
		}
	}
}
