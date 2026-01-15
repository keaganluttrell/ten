package main

import (
	"flag"
	"log"
	"os"

	"github.com/keaganluttrell/ten/ssr"
)

func main() {
	var (
		kernelAddr   = flag.String("kernel", "127.0.0.1:9000", "Kernel address")
		factotumAddr = flag.String("factotum", "127.0.0.1:9001", "Factotum address")
		addr         = flag.String("addr", ":8080", "HTTP listen address")
	)
	flag.Parse()

	if v := os.Getenv("KERNEL_ADDR"); v != "" {
		*kernelAddr = v
	}
	if v := os.Getenv("FACTOTUM_ADDR"); v != "" {
		*factotumAddr = v
	}
	if v := os.Getenv("ADDR"); v != "" {
		*addr = v
	}

	if err := ssr.Start(*addr, *kernelAddr, *factotumAddr); err != nil {
		log.Fatal(err)
	}
}
