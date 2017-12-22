package main

import "fmt"
import "os"
import "net"

// Increments an IP address.  Only works for Ipv4.
// It seems strange that this isn't built into the default net.IP,
// but I guess it's not a common operation.
func increment_ip(ip net.IP) net.IP {
	v4 := ip.To4()
	for i := 3; i >= 0; i-- {
		if v4[i] < 255 {
			v4[i] += 1
			return v4
		}

		v4[i] = 0
	}
	fmt.Println(v4[3])
	return v4
}

func scan_address(ip net.IP) {
	fmt.Println(ip)
	conn, err := net.Dial("tcp", ip.String()+":22")
	if err != nil {
		fmt.Printf("Connection error: %s\n", err)
		return
	}

	output := make([]byte, 4096)
	for {
		n, err := conn.Read(output)
		if err != nil {
			fmt.Printf("Read error: %s\n", err)
			break
		}
		fmt.Printf("Read %d bytes", n)
		fmt.Printf("output: %s", output[:n])
	}
}

func scan_subnet(subnet_cidr string) {
	fmt.Println("scanning subnet: " + subnet_cidr)
	address, network, _ := net.ParseCIDR(subnet_cidr)
	fmt.Println("address: " + address.String())
	fmt.Println("mask: " + network.Mask.String())

	for ; network.Contains(address); address = increment_ip(address) {
		scan_address(address)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("syntax: sshscanner <subnet-cidr>")
		os.Exit(1)
	}
	subnet := os.Args[1]
	scan_subnet(subnet)
}
