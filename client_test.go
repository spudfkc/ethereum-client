package main

import (
	"testing"
	"fmt"
	"net"
)

func TestEndpointPack(t *testing.T) {
	addr := net.ParseIP("192.168.1.1")
	endpoint := EndPoint{addr, 1111, 2222}

	packed := endpoint.Pack()

	fmt.Printf("Packed struct: %v", packed)
}

func TestPingNodePack(t *testing.T) {

}
