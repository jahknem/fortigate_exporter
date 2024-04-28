package probe

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/bluecmd/fortigate_exporter/pkg/http"
	"github.com/prometheus/client_golang/prometheus"
)

type FirewallAddressResult struct {
	Name   string `json:"name"`
	Subnet string `json:"subnet"`
	Type   string `json:"type"`
}

type FirewallAddressData struct {
	Results []FirewallAddressResult `json:"results"`
	VDOM    string                  `json:"vdom"`
}

type SubnetMatch struct {
	Address FirewallAddressResult
	VDOM    string
}

type FirewallAddresses []FirewallAddressData

func probeFirewallAddress(c http.FortiHTTP, meta *TargetMetadata) ([]prometheus.Metric, bool) {
	var firewallAddresses FirewallAddresses

	if err := c.Get("/api/v2/cmdb/firewall/address", "vdom=*", &firewallAddresses); err != nil {
		log.Printf("Error fetching firewall addresses: %v", err)
		return nil, false
	}

	userFirewalls, err := fetchUserFirewallData(c)
	if err != nil {
		log.Printf("Error fetching user firewall data: %v", err)
		return nil, false
	}

	userCountDesc := prometheus.NewDesc(
		"fortigate_user_count_per_subnet",
		"Number of active users per subnet",
		[]string{"subnet_name", "subnet", "vdom"},
		nil,
	)

	var metrics []prometheus.Metric
	subnetUserCounts := make(map[string]map[string]int)

	for _, fw := range userFirewalls {
		for _, result := range fw.Results {
			userIP := net.ParseIP(result.IPAddr)
			matches := findLongestPrefixMatch(userIP, firewallAddresses)
			for _, match := range matches {
				vdom := match.VDOM
				address := match.Address
				if subnetUserCounts[vdom] == nil {
					subnetUserCounts[vdom] = make(map[string]int)
				}
				subnetUserCounts[vdom][address.Name]++
			}
		}
	}

	for vdom, subnets := range subnetUserCounts {
		for name, count := range subnets {
			metrics = append(metrics, prometheus.MustNewConstMetric(
				userCountDesc, prometheus.GaugeValue, float64(count), name, name, vdom,
			))
		}
	}

	return metrics, true
}

func findLongestPrefixMatch(userIP net.IP, addresses FirewallAddresses) []SubnetMatch {
	var longestMatches []SubnetMatch
	longestPrefix := 0

	for _, data := range addresses {
		for _, address := range data.Results {
			ipMask := strings.Split(address.Subnet, " ")
			if len(ipMask) != 2 {
				log.Printf("Invalid subnet format: %s", address.Subnet)
				continue
			}
			cidr, err := ipNetToCIDR(ipMask[0], ipMask[1])
			if err != nil {
				log.Printf("Error converting IP/Mask to CIDR: %v", err)
				continue
			}

			_, subnet, err := net.ParseCIDR(cidr)
			if err != nil {
				log.Printf("Error parsing CIDR '%s': %v", cidr, err)
				continue
			}

			if subnet.Contains(userIP) {
				maskSize, _ := subnet.Mask.Size()
				if maskSize > longestPrefix {
					longestPrefix = maskSize
					longestMatches = []SubnetMatch{{Address: address, VDOM: data.VDOM}}
				} else if maskSize == longestPrefix {
					longestMatches = append(longestMatches, SubnetMatch{Address: address, VDOM: data.VDOM})
				}
			}
		}
	}

	return longestMatches
}

func ipNetToCIDR(ip string, mask string) (string, error) {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return "", fmt.Errorf("invalid IP address")
	}
	maskIP := net.ParseIP(mask)
	if maskIP == nil {
		return "", fmt.Errorf("invalid mask")
	}
	ones, _ := net.IPMask(maskIP.To4()).Size()
	return fmt.Sprintf("%s/%d", ip, ones), nil
}
