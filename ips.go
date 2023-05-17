package resolver

import (
	"net"
	"sync"
	"sync/atomic"
)

// ips ...
type ips struct {
	mu     sync.RWMutex
	ipIdx  uint64
	ipList []net.IP
}

// newIps ...
func newIps() *ips {
	return &ips{
		ipList: make([]net.IP, 0),
	}
}

func newIpsFromList(listIP []string) *ips {
	result := make([]net.IP, 0, len(listIP))
	for _, v := range listIP {
		ip := net.ParseIP(v)
		if ip != nil {
			result = append(result, ip)
		}
	}
	return &ips{
		ipList: result,
	}
}

// setIpList ...
func (i *ips) setIpList(ipList []net.IP) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.ipList = ipList
}

// getNextIPWithIndex ...
func (i *ips) getNextIPWithIndex() (net.IP, int) {
	i.mu.RLock()
	if len(i.ipList) == 0 {
		i.mu.RUnlock()
		return nil, 0
	}

	idx := i.ipIdx % uint64(len(i.ipList))
	ipRet := i.ipList[idx]
	i.mu.RUnlock()

	atomic.AddUint64(&i.ipIdx, 1)

	return ipRet, int(idx)
}

// getList ...
func (i *ips) getList() []net.IP {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.ipList
}
