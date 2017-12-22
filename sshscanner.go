package main

import "fmt"
import "io"
import "os"
import "math"
import "net"
import "time"
import "flag"

// Increments an IP address.  Only works for Ipv4.
// It seems strange that this isn't built into the default net.IP,
// but I guess it's not a common operation.
func increment_ip(ip net.IP) {
	v4 := ip.To4()
	for i := 3; i >= 0; i-- {
		if v4[i] < 255 {
			v4[i] += 1
			return
		}

		v4[i] = 0
	}
	return
}

func scan_address(ip net.IP, results chan<- string, errors chan<- string, timeout_secs int) {
	timeout := time.Duration(timeout_secs) * time.Second
	conn, err := net.DialTimeout("tcp", ip.String()+":22", timeout)
	if err != nil {
		errors <- fmt.Sprintf("Connection error: %s\n", err)
		return
	}

	output := make([]byte, 4096)
	for {
		conn.SetReadDeadline(time.Now().Add(timeout))
		n, err := conn.Read(output)
		if err != nil {
			if err != io.EOF {
				errors <- fmt.Sprintf("%s: read error %s\n", ip, err)
				break
			}
			if n == 0 {
				errors <- fmt.Sprintf("%s: EOF with no data\n", ip)
				break
			}
		}
		results <- fmt.Sprintf("%s %s", ip.String(), output[:n])
		if n > 0 {
			break
		}
	}
	conn.Close()
}

func scan_subnet(subnet_cidr string, concurrency int, timeout int) {
	_, network, _ := net.ParseCIDR(subnet_cidr)
	results := make(chan string, 100)
	errors := make(chan string, 100)
	addy := make(net.IP, len(network.IP))
	copy(addy, network.IP)
	current := 0
	total := 0
	max := concurrency
	bits, _ := network.Mask.Size()
	size := int(math.Pow(2, float64(32-bits)))
	for {
		for current <= max {
			dup := make(net.IP, len(addy))
			copy(dup, addy)
			go scan_address(dup, results, errors, timeout)
			increment_ip(addy)
			current++
		}

		select {
		case result := <-results:
			total++
			current--
			fmt.Print(result)
		case error_msg := <-errors:
			fmt.Fprint(os.Stderr, error_msg)
			total++
			current--
		}

		if total == size {
			break
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("syntax: sshscanner <subnet-cidr>")
		os.Exit(1)
	}
	concurrency := flag.Int("concurrency", 200, "number of simultaneous connections")
	timeout := flag.Int("timeout", 10, "connection timeout in seconds")
	flag.Parse()
	fmt.Println(*concurrency)
	subnet := flag.Args()[0]
	scan_subnet(subnet, *concurrency, *timeout)
}
