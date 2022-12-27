package resolver

import (
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"time"

	logApi "github.com/woody-ltd/go/api/log"
)

// Resolver ...
type Resolver struct {
	mu sync.RWMutex

	// tag - the string to identify this instance of resolver among the others
	tag string

	// hosts - a map with maintained hosts
	hosts map[string]*host

	// dnsClient - a network client that can use a list of nameservers to lookup hosts and retrieve its ip addresses with ttl
	dnsClient *dnsClient

	// logger - a logger which used in this package
	logger logApi.Logger

	// stopCh ...
	stopCh chan struct{}
}

// New returns ResolverService instance
func New(tag string, logger logApi.Logger) *Resolver {
	r := &Resolver{
		tag:       tag,
		hosts:     make(map[string]*host),
		dnsClient: newDnsClient(logger),
		logger:    logger,
		stopCh:    make(chan struct{}),
	}

	go r.oldHostsDeleteLoop()

	return r
}

// WithNameservers - sets nameservers to resolve hosts
func (r *Resolver) WithNameservers(nameServers ...string) *Resolver {
	r.dnsClient.setNameServers(nameServers)
	return r
}

// AddHost adds a host to maintaining
func (r *Resolver) AddHost(hostName string) {
	r.mu.RLock()
	_, ok := r.hosts[hostName]
	r.mu.RUnlock()

	if ok {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.hosts[hostName]; !ok {
		r.hosts[hostName] = newHost(r.tag, hostName, true, r.dnsClient, r.logger)
	}
}

// DelHost deletes a host with name hostName from maintaining
func (r *Resolver) DelHost(hostName string) {
	r.delHosts([]string{hostName})
}

// Stop - stops maintaining for all hosts
func (r *Resolver) Stop() {
	close(r.stopCh)
}

// GetNextIP returns next IPv4 for host with name hostName
func (r *Resolver) GetNextIP(hostName string) string {
	ip, _ := r.GetNextIPWithIdx(hostName)
	return ip
}

// GetNextIPWithIdx returns next IPv4 and index for host with name hostName
func (r *Resolver) GetNextIPWithIdx(hostName string) (string, int) {
	r.mu.RLock()
	h, ok := r.hosts[hostName]
	r.mu.RUnlock()

	if ok {
		ip, idx := h.getNextIP4WithIndex()
		return ipStrIdx(ip, idx)
	}

	r.mu.Lock()
	if h, ok = r.hosts[hostName]; !ok {
		h = newHost(r.tag, hostName, false, r.dnsClient, r.logger)
		r.hosts[hostName] = h
	}
	r.mu.Unlock()

	ip, idx := h.getNextIP4WithIndex()
	return ipStrIdx(ip, idx)
}

// GetNextIP6 returns next IPv6 for host with name hostName
func (r *Resolver) GetNextIP6(hostName string) string {
	ip, _ := r.GetNextIP6WithIdx(hostName)
	return ip
}

// GetNextIP6WithIdx returns next IPv6 and index for host with name hostName
func (r *Resolver) GetNextIP6WithIdx(hostName string) (string, int) {
	r.mu.RLock()
	h, ok := r.hosts[hostName]
	r.mu.RUnlock()

	if ok {
		ip, idx := h.getNextIP6WithIndex()
		return ipStrIdx(ip, idx)
	}

	r.mu.Lock()
	if h, ok = r.hosts[hostName]; !ok {
		h = newHost(r.tag, hostName, false, r.dnsClient, r.logger)
		r.hosts[hostName] = h
	}
	r.mu.Unlock()

	ip, idx := h.getNextIP6WithIndex()
	return ipStrIdx(ip, idx)
}

// GetIPs returns a list of IPv4 and IPv6
func (r *Resolver) GetIPs(hostName string) ([]net.IP, []net.IP) {
	r.mu.RLock()
	h := r.hosts[hostName]
	r.mu.RUnlock()

	if h == nil {
		return nil, nil
	}

	return h.getIPs()
}

// GetIPsStr returns a string list of IPv4 and IPv6
func (r *Resolver) GetIPsStr(hostName string) ([]string, []string) {
	ip4, ip6 := r.GetIPs(hostName)
	var ip4Str, ip6Str []string
	for _, ip := range ip4 {
		ip4Str = append(ip4Str, ip.String())
	}
	for _, ip := range ip6 {
		ip6Str = append(ip6Str, ip.String())
	}
	return ip4Str, ip6Str
}

// LookupSRV makes LookupSRV request to one of nameserver passed to WithNameservers
func (r *Resolver) LookupSRV(service, proto, name string) (string, []*net.SRV, error) {
	return r.dnsClient.lookupSRV(service, proto, name)
}

// Dump dumps into writer all hosts with theirs ips
func (r *Resolver) Dump(w io.Writer) {
	r.DumpPrefix(w, "")
}

// DumpPrefix dumps with prefix into writer all hosts with theirs ips
func (r *Resolver) DumpPrefix(w io.Writer, prefix string) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	hosts := make([]string, 0, len(r.hosts))
	for host := range r.hosts {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	for _, hostName := range hosts {
		ip4, ip6 := r.GetIPsStr(hostName)
		sort.Strings(ip4)
		sort.Strings(ip6)

		for idx, ip := range ip4 {
			fmt.Fprintf(w, "%sresolver.v4.%s.%d: %s\n", prefix, hostName, idx, ip)
		}
		for idx, ip := range ip6 {
			fmt.Fprintf(w, "%sresolver.v6.%s.%d: %s\n", prefix, hostName, idx, ip)
		}
	}
}

// oldHostsDeleteLoop runs a loop that deletes old hosts that were added non-explicitly
func (r *Resolver) oldHostsDeleteLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			r.logger.Info().Println(r.tag, "Stop resolving hosts")
			r.emptyHosts()
			return
		case <-ticker.C:
			hostsToDel := make([]string, 0)
			r.mu.RLock()
			for hostName := range r.hosts {
				if r.hosts[hostName].isOld() && !r.hosts[hostName].isExplicitlyAdded() {
					hostsToDel = append(hostsToDel, hostName)
				}
			}
			r.mu.RUnlock()

			if len(hostsToDel) > 0 {
				r.delHosts(hostsToDel)
				r.logger.Info().Println(r.tag, "Deleted old hosts:", hostsToDel)
			}
		}
	}
}

// delHosts deletes hosts from maintaining
func (r *Resolver) delHosts(hosts []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, h := range hosts {
		delete(r.hosts, h)
	}
}

// emptyHosts deletes all hosts from maintaining
func (r *Resolver) emptyHosts() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for hostName := range r.hosts {
		r.hosts[hostName].stop()
	}
	r.hosts = make(map[string]*host)
}

func ipStrIdx(ip net.IP, idx int) (string, int) {
	if ip == nil {
		return "", -1
	}
	return ip.String(), idx
}
