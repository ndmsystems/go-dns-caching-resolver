package resolver

import (
	"context"
	"log"
	"math"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	logApi "github.com/woody-ltd/go/api/log"
	"golang.org/x/sync/errgroup"
)

const (
	defaultTtl = 60 // 60 sec
)

// iDnsClient ...
type iDnsClient interface {
	setNameServers(nameServers []string)
	lookupHost(ctx context.Context, host string) ([]net.IP, []net.IP, uint32, error)
}

// dnsClient ...
type dnsClient struct {
	sync.RWMutex
	nsCounter   uint64
	nameServers []string
	logger      logApi.Logger
}

// newDnsClient ...
func newDnsClient(logger logApi.Logger) *dnsClient {
	return &dnsClient{
		logger: logger,
	}
}

// setNameServers ...
func (d *dnsClient) setNameServers(nameServers []string) {
	ns := parseNameServers(nameServers)
	d.Lock()
	defer d.Unlock()
	d.nameServers = ns
}

// lookupHost ...
func (d *dnsClient) lookupHost(ctx context.Context, host string) ([]net.IP, []net.IP, uint32, error) {
	d.RLock()
	nsCnt := len(d.nameServers)
	d.RUnlock()

	if nsCnt == 0 {
		ips := make(map[bool][]net.IP)
		addrs, err := net.LookupHost(host)
		if err != nil {
			return nil, nil, defaultTtl, nil
		}
		for _, addr := range addrs {
			if netIP := net.ParseIP(addr); netIP != nil {
				isV6 := strings.Contains(addr, ":")
				ips[isV6] = append(ips[isV6], netIP)
			}
		}
		return ips[false], ips[true], defaultTtl, nil
	}

	var (
		ip4, ip6 []net.IP
		ttl      uint32
		err      error
	)

	for i := 0; i < nsCnt; i++ {
		d.RLock()
		nsIdx := int(atomic.LoadUint64(&d.nsCounter)) % len(d.nameServers)
		nServer := d.nameServers[nsIdx]
		d.RUnlock()

		ip4, ip6, ttl, err = d.dnsLookupHost(ctx, nServer, host)
		if err == nil {
			break
		}
		atomic.AddUint64(&d.nsCounter, 1)
	}

	return ip4, ip6, ttl, err
}

// dnsLookupHost ...
func (d *dnsClient) dnsLookupHost(ctx context.Context, nServer, host string) ([]net.IP, []net.IP, uint32, error) {
	var ip4, ip6 []net.IP
	g, _ := errgroup.WithContext(ctx)

	var ttl4, ttl6 uint32 = math.MaxUint32, math.MaxUint32

	// get IPv4 addresses
	g.Go(func() error {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(host), dns.TypeA)
		in, err := dns.Exchange(m, nServer+":53")
		if err != nil {
			return err
		}
		for _, rr := range in.Answer {
			if dnsRec, ok := rr.(*dns.A); ok {
				ip4 = append(ip4, dnsRec.A)
				if dnsRec.Header().Ttl < ttl4 {
					ttl4 = dnsRec.Header().Ttl
				}
			}
		}
		return nil
	})

	// get IPv6 addresses
	g.Go(func() error {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(host), dns.TypeAAAA)
		in, err := dns.Exchange(m, nServer+":53")
		if err != nil {
			return err
		}
		for _, rr := range in.Answer {
			if dnsRec, ok := rr.(*dns.AAAA); ok {
				ip6 = append(ip6, dnsRec.AAAA)
				if dnsRec.Header().Ttl < ttl6 {
					ttl6 = dnsRec.Header().Ttl
				}
			}
		}
		return nil
	})

	var ttl uint32 = defaultTtl
	if ttl4 > defaultTtl && ttl4 != math.MaxUint32 {
		ttl = ttl4
	}
	if ttl6 > defaultTtl && ttl6 != math.MaxUint32 && ttl6 < ttl4 {
		ttl = ttl6
	}

	return ip4, ip6, ttl, g.Wait()
}

// parseNameServers ...
func parseNameServers(nameServers []string) []string {
	ret := make([]string, 0, len(nameServers))
	for _, ns := range nameServers {
		if addr := net.ParseIP(ns); addr == nil {
			log.Printf("nameserver %s is not valid\n", ns)
			continue
		}
		ret = append(ret, ns)
	}
	return ret
}
