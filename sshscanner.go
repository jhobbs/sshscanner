package main

import "fmt"
import "io"
import "os"
import "math"
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
	return v4
}

func scan_address(ip net.IP, ch chan<- string) {
	conn, err := net.Dial("tcp", ip.String()+":22")
	if err != nil {
		ch <- fmt.Sprintf("Connection error: %s\n", err)
		return
	}

	output := make([]byte, 4096)
	for {
		n, err := conn.Read(output)
		if err != nil {
			if err != io.EOF {
				ch <- fmt.Sprintf("read error: %s\n", err)
				ch <- fmt.Sprintf("%s: read error %s\n", ip, err)
				break
			}
			if n == 0 {
				ch <- fmt.Sprintf("%s: EOF with no data\n", ip)
				break
			}
		}
		ch <- fmt.Sprintf("%s %s", ip.String(), output[:n])
		if n > 0 {
			break
		}
	}
	conn.Close()
}

func scan_subnet(subnet_cidr string) {
	address, network, _ := net.ParseCIDR(subnet_cidr)
	ch := make(chan string)
	for ; network.Contains(address); address = increment_ip(address) {
		dup := make(net.IP, len(address))
		copy(dup, address)
		go scan_address(dup, ch)
	}

	bits, _ := network.Mask.Size()
	size := int(math.Pow(2, float64(32-bits)))
	for i := 0; i < size-1; i++ {
		fmt.Print(<-ch)
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
