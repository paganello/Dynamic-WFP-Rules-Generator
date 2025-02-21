package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"prg/firewall"
	"syscall"
)

func main() {

	var session uintptr

	session, err := firewall.CreateWfpSession()
	if err != nil {
		log.Fatalf("Failed to create WFP session: %v", err)
	}
	defer func() {
		if err := firewall.FwpmEngineClose0(session); err != nil {
			log.Printf("Warning: Failed to close WFP session: %v", err)
		}
	}()

	baseObjects, err := firewall.RegisterBaseObjects(session)
	if err != nil {
		log.Fatalf("Failed to register base objects: %v", err)
	}

	err = firewall.PermitCIDR(session, baseObjects, 10, "10.0.0.116/32")
	if err != nil {
		log.Fatalf("Failed to add custom firewall rule: %v", err)
	}

	fmt.Println("Firewall rule successfully added")

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("Waiting termination signal...")
	<-sigs
	fmt.Println("Termination signal received.")
}
