package resolver

import (
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	logApi "github.com/tdx/go/api/log"
	resolverApi "github.com/tdx/go/api/resolver"
)

type ips struct {
	idx  int
	ip4  []string
	ip6  []string
	ipv4 []net.IP
	ipv6 []net.IP
}

type svc struct {
	mu    sync.RWMutex
	hosts map[string]*ips
	tag   string
	log   logApi.Logger
}

// New returns ResolverService instance
func New(tag string, log logApi.Logger) resolverApi.ResolverService {

	s := &svc{
		hosts: make(map[string]*ips),
		tag:   tag,
		log:   log,
	}

	return s
}

func (s *svc) AddHost(host string) {

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.hosts[host]; ok {
		return
	}

	s.hosts[host] = &ips{}

	go func(p *svc) {
		s.log.Info().Println(s.tag, "start resolver for:", host)
		for {
			ips, err := net.LookupHost(host)
			if err == nil {
				if !p.updateHostIPs(host, ips) {
					s.log.Error().Println(s.tag, "stop resolver for:", host)
					return
				}
			} else {
				s.log.Error().Println(s.tag, "resolve", host, "failed:", err)
			}

			time.Sleep(time.Duration(60 * time.Second))
		}
	}(s)
}

func (s *svc) DelHost(host string) {
	s.mu.Lock()
	delete(s.hosts, host)
	s.mu.Unlock()
}

func (s *svc) GetNextIP(host string) string {

	s.mu.Lock()
	defer s.mu.Unlock()

	if r, ok := s.hosts[host]; ok {

		itemsCount := len(r.ip4)
		if itemsCount == 0 {
			return ""
		}

		r.idx = (r.idx + 1) % itemsCount

		return r.ip4[r.idx]
	}

	return ""
}

func (s *svc) GetIPs(host string) ([]net.IP, []net.IP) {

	s.mu.RLock()
	hosts := s.hosts[host]
	s.mu.RUnlock()

	if hosts == nil {
		return nil, nil
	}

	return hosts.ipv4, hosts.ipv6
}

func (s *svc) GetIPsStr(host string) ([]string, []string) {
	s.mu.RLock()
	hosts := s.hosts[host]
	s.mu.RUnlock()

	if hosts == nil {
		return nil, nil
	}

	return hosts.ip4, hosts.ip6
}

func (s *svc) Dump(w io.Writer) {

	s.mu.RLock()
	defer s.mu.RUnlock()

	for host, r := range s.hosts {
		for idx, ip := range r.ip4 {
			fmt.Fprintf(w, "resolver.v4.%s.%d: %s\n", host, idx, ip)
		}
		for idx, ip := range r.ip6 {
			fmt.Fprintf(w, "resolver.v6.%s.%d: %s\n", host, idx, ip)
		}
	}
}

//
func (s *svc) updateHostIPs(host string, sip []string) bool {

	s.mu.RLock()
	r, ok := s.hosts[host]
	s.mu.RUnlock()

	if !ok {
		return false
	}

	var (
		ipsv4 []string
		ipsv6 []string
		ipv4  []net.IP
		ipv6  []net.IP
	)

	for _, ip := range sip {

		ipp := net.ParseIP(ip)
		if ipp == nil {
			continue
		}

		if strings.Contains(ip, ":") {
			ipv6 = append(ipv6, ipp)
			ipsv6 = append(ipsv6, ip)
		} else {
			ipv4 = append(ipv4, ipp)
			ipsv4 = append(ipsv4, ip)
		}
	}
	sort.Strings(ipsv4)
	sort.Strings(ipsv6)

	r.ip4 = ipsv4
	r.ip6 = ipsv6
	r.ipv4 = ipv4
	r.ipv6 = ipv6

	if r.idx > len(ipsv4)-1 {
		r.idx = 0
	}

	s.log.Debug().Println(s.tag, "host:", host, "ips4:", ipsv4, "ips6:", ipsv6)

	return true
}
