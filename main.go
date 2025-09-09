package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp_dropper.c -- -I/usr/include/x86_64-linux-gnu -I/usr/include/asm-generic

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Usage: go run . <interface-name> [port]")
	}
	ifaceName := os.Args[1]

	targetPort := 4040
	if len(os.Args) > 2 {
		port, err := strconv.Atoi(os.Args[2])
		if err != nil {
			log.Fatalf("Invalid port: %s", os.Args[2])
		}
		targetPort = port
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Removing memlock limit: %s", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Loading eBPF objects: %s", err)
	}
	defer objs.Close()

	key := uint32(0)
	port := uint16(targetPort)
	if err := objs.PortMap.Put(key, port); err != nil {
		log.Fatalf("Updating port map: %s", err)
	}
	log.Printf("Set allowed TCP port in eBPF map: %d", targetPort)

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Looking up interface %s: %s", ifaceName, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpDropper,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Attaching XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("eBPF program attached to %s. Allowing only TCP port %d.", ifaceName, targetPort)
	log.Println("Press Ctrl+C to exit.")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper

	log.Println("Detaching program and exiting.")
}
