package main

import (
	_"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	_"time"
	_"fmt"
	"net"


	log "github.com/sirupsen/logrus"

	_"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/dropbox/goebpf"
)

const (
	defaultAddr     = "127.0.0.1:50051"
	defaultN4Addr   = "127.0.0.1:8805"
	defaultN3Addr   = "193.168.1.3"
	defaultDeviceID = 0
	UPLINK = 1
	DOWNLINK = 2
)

func pfcp_SessionEstablish_handle(msg message.Message,addr net.Addr){
	log.Info("ignored undecodable message:%s, addr:%s",msg,addr)

}

func n4Server(listen *string){
	laddr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		log.Fatalf("Cannot resolve n4 addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatalf("Cannot start n4 socket: %v",err)
	}

	buf := make([]byte, 1500)
	for{
		log.Info("input")
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Fatal(err)
		}
		log.Info("message len:%d",n)
		msg, err := message.Parse(buf[:n])
		if err != nil {
			log.Info("ignored undecodable message: %x, error: %s msg:%s", buf[:n], err,msg)
			continue
		}
		switch(msg.MessageTypeName()){
			case "Session Establishment Request":
				log.Info("message.SessionEstablishmentRequest")
				pfcp_SessionEstablish_handle(msg,addr)
			default:
				log.Info("unknow pfcp message")
		}
	}
}

func printBpfInfo(bpf goebpf.System) {
	fmt.Println("Maps:")
	for _, item := range bpf.GetMaps() {
		fmt.Printf("\t%s: %v, Fd %v\n", item.GetName(), item.GetType(), item.GetFd())
	}
	fmt.Println("\nPrograms:")
	for _, prog := range bpf.GetPrograms() {
		fmt.Printf("\t%s: %v, size %d, license \"%s\"\n",
			prog.GetName(), prog.GetType(), prog.GetSize(), prog.GetLicense(),
		)

	}
	fmt.Println()
}

func main() {
	var verbose bool
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose mode with debug log messages")
	var n4Addr string
	flag.StringVar(&n4Addr,"n4addr",defaultN4Addr,"N4 server socket")
	var iface string
	flag.StringVar(&iface,"iface", "", "Interface to bind XDP UPF N3/N6")
	var elf string
	flag.StringVar(&elf,"elf", "upf.elf", "clang/llvm compiled binary file")
	var test bool
	flag.BoolVar(&test, "test", true, "mock and testing")
	flag.Parse()

	if verbose {
		log.SetLevel(log.DebugLevel)
	}

	// Create eBPF system
	bpf := goebpf.NewDefaultEbpfSystem()
	// Load .ELF files compiled by clang/llvm
	err := bpf.LoadElf(elf)
	if err != nil {
		log.Fatalf("LoadElf() failed: %v", err)
	}
	printBpfInfo(bpf)
	xdp := bpf.GetProgramByName("upf_input")
	if xdp == nil {
		log.Fatalf("Program 'upf_input' not found.")
	}
	// Load XDP program into kernel
	err = xdp.Load()
	if err != nil {
		log.Fatalf("xdp.Load(): %v", err)
	}

	// Find special "PERF_EVENT" eBPF map
	m_teid_pdrs := bpf.GetMapByName("m_teid_pdrs")
	if m_teid_pdrs == nil {
		log.Fatalf("eBPF map 'm_teid_pdrs' not found")
	}

	// Attach to interface
	err = xdp.Attach(iface)
	if err != nil {
		log.Fatalf("xdp.Attach(): %v", err)
	}
	defer xdp.Detach()

	if test{
		err := m_teid_pdrs.Upsert(0x1111, 0x01010101)
		if err != nil {
			log.Fatalf("Unable to Insert into eBPF map: %v", err)
		}
	}

	log.Infof("UPF control endpoint at %s", n4Addr)
	/*N4 server start*/
	go n4Server(&n4Addr)
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)

	for {
		select {
		case <-ctrlC:
			fmt.Println("\nDetaching program and exit")
			return
		}
	}
}