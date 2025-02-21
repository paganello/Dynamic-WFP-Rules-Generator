package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"prg/firewall"
	"syscall"
)

func main() {
	// Define command line flags
	permitFlag := flag.Bool("permit", false, "Permit traffic for specified CIDR")
	blockFlag := flag.Bool("block", false, "Block traffic for specified CIDR")
	flag.Parse()

	// Check if CIDR is provided as argument
	if flag.NArg() != 1 {
		log.Fatal("Usage: program [-permit|-block] CIDR")
	}

	// Get CIDR from arguments
	cidr := flag.Arg(0)

	// Check if exactly one flag is specified
	if (*permitFlag && *blockFlag) || (!*permitFlag && !*blockFlag) {
		log.Fatal("Exactly one flag (-permit or -block) must be specified")
	}

	// Create WFP session
	session, err := firewall.CreateWfpSession()
	if err != nil {
		log.Fatalf("Failed to create WFP session: %v", err)
	}
	defer func() {
		if err := firewall.FwpmEngineClose0(session); err != nil {
			log.Printf("Warning: Failed to close WFP session: %v", err)
		}
	}()

	// Register base objects
	baseObjects, err := firewall.RegisterBaseObjects(session)
	if err != nil {
		log.Fatalf("Failed to register base objects: %v", err)
	}

	// Apply the rule based on the flag
	if *permitFlag {
		err = firewall.PermitCIDR(session, baseObjects, 10, cidr)
		if err != nil {
			log.Fatalf("Failed to add permit rule: %v", err)
		}
		fmt.Printf("Permit rule for %s successfully added\n", cidr)
	} else {
		err = firewall.BlockCIDR(session, baseObjects, 10, cidr)
		if err != nil {
			log.Fatalf("Failed to add block rule: %v", err)
		}
		fmt.Printf("Block rule for %s successfully added\n", cidr)
	}

	fmt.Println("Rule will remain active until termination signal is received")

	// Wait for termination signal
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("Waiting for termination signal...")
	<-sigs
	fmt.Println("Termination signal received.")
}