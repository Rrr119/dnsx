package dnsx

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	miekgdns "github.com/miekg/dns"
	retryabledns "github.com/projectdiscovery/retryabledns"
	"github.com/stretchr/testify/require"
)

// testDNSServer is an in-process DNS server used to exercise the bulk
// resolver without external network access.
type testDNSServer struct {
	addr   string
	server *miekgdns.Server
}

func startTestDNSServer(t testing.TB, handler miekgdns.HandlerFunc) *testDNSServer {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &miekgdns.Server{PacketConn: packetConn, Handler: handler}
	go func() {
		_ = server.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = server.Shutdown()
	})
	return &testDNSServer{addr: packetConn.LocalAddr().String(), server: server}
}

// aRecordHandler answers every A query with the given IPv4 addresses and
// NXDOMAIN for names under "nx.".
func aRecordHandler(ips ...string) miekgdns.HandlerFunc {
	return func(w miekgdns.ResponseWriter, r *miekgdns.Msg) {
		msg := new(miekgdns.Msg)
		msg.SetReply(r)
		name := strings.TrimSuffix(r.Question[0].Name, ".")
		if strings.HasPrefix(name, "nx.") {
			msg.SetRcode(r, miekgdns.RcodeNameError)
			_ = w.WriteMsg(msg)
			return
		}
		for _, ip := range ips {
			msg.Answer = append(msg.Answer, &miekgdns.A{
				Hdr: miekgdns.RR_Header{Name: r.Question[0].Name, Rrtype: miekgdns.TypeA, Class: miekgdns.ClassINET, Ttl: 300},
				A:   net.ParseIP(ip),
			})
		}
		_ = w.WriteMsg(msg)
	}
}

func newTestBulkResolver(t *testing.T, resolvers []string, retry RetryPolicy) *BulkResolver {
	t.Helper()
	bulk, err := NewBulkResolver(BulkOptions{
		Resolvers:   resolvers,
		Concurrency: 32,
		Retry:       retry,
		Pool:        PoolOptions{Timeout: 2 * time.Second},
	})
	require.NoError(t, err)
	return bulk
}

func TestResolverPoolRoundRobin(t *testing.T) {
	pool, err := NewResolverPool([]string{"udp:127.0.0.1:53", "udp:127.0.0.2:53", "udp:127.0.0.2:53"}, PoolOptions{})
	require.NoError(t, err)
	require.Equal(t, 2, pool.Size(), "duplicate resolvers must be deduplicated")

	seen := map[string]int{}
	for i := 0; i < 4; i++ {
		seen[pool.next().addr]++
	}
	require.Equal(t, 2, seen["udp:127.0.0.1:53"])
	require.Equal(t, 2, seen["udp:127.0.0.2:53"])
}

func TestResolverPoolSkipsUnhealthy(t *testing.T) {
	pool, err := NewResolverPool([]string{"udp:127.0.0.1:53", "udp:127.0.0.2:53"}, PoolOptions{
		MaxConsecutiveFailures: 2,
		FailureCooldown:        time.Minute,
	})
	require.NoError(t, err)

	bad := pool.resolvers[0]
	bad.report(true)
	bad.report(true)

	for i := 0; i < 5; i++ {
		require.Equal(t, "udp:127.0.0.2:53", pool.next().addr, "unhealthy resolver must be skipped during cooldown")
	}

	bad.report(false)
	require.True(t, bad.healthy(pool.options), "a successful query must reset the failure counter")
}

func TestBulkResolveRetryOnServfail(t *testing.T) {
	// The server fails the first two queries for every host, then answers.
	var mu sync.Mutex
	counts := map[string]int{}
	flaky := func(w miekgdns.ResponseWriter, r *miekgdns.Msg) {
		mu.Lock()
		counts[r.Question[0].Name]++
		count := counts[r.Question[0].Name]
		mu.Unlock()
		if count < 3 {
			msg := new(miekgdns.Msg)
			msg.SetRcode(r, miekgdns.RcodeServerFailure)
			_ = w.WriteMsg(msg)
			return
		}
		aRecordHandler("10.0.0.1")(w, r)
	}
	server := startTestDNSServer(t, flaky)

	bulk := newTestBulkResolver(t, []string{"udp:" + server.addr}, RetryPolicy{
		MaxAttempts:    3,
		InitialBackoff: time.Millisecond,
		MaxBackoff:     5 * time.Millisecond,
		Multiplier:     2,
	})

	result := bulk.Resolve(context.Background(), "retry.example.com")
	require.NotNil(t, result.Data, "third attempt must succeed")
	require.Equal(t, 3, result.Attempts)
	require.Equal(t, []string{"10.0.0.1"}, result.Data.A)

	stats := bulk.Stats()
	require.Equal(t, uint64(3), stats.Queries)
	require.Equal(t, uint64(2), stats.Retries)
}

func TestBulkResolveRetriesExhausted(t *testing.T) {
	server := startTestDNSServer(t, func(w miekgdns.ResponseWriter, r *miekgdns.Msg) {
		msg := new(miekgdns.Msg)
		msg.SetRcode(r, miekgdns.RcodeServerFailure)
		_ = w.WriteMsg(msg)
	})
	bulk := newTestBulkResolver(t, []string{"udp:" + server.addr}, RetryPolicy{
		MaxAttempts:    2,
		InitialBackoff: time.Millisecond,
		MaxBackoff:     5 * time.Millisecond,
		Multiplier:     2,
	})

	result := bulk.Resolve(context.Background(), "down.example.com")
	require.Nil(t, result.Data)
	require.Equal(t, 2, result.Attempts)
	require.ErrorIs(t, result.Err, ErrBulkRetriesExceeded)
}

func TestBulkResolveNoRetryOnNXDOMAIN(t *testing.T) {
	server := startTestDNSServer(t, aRecordHandler("10.0.0.1"))
	bulk := newTestBulkResolver(t, []string{"udp:" + server.addr}, RetryPolicy{
		MaxAttempts:    5,
		InitialBackoff: time.Millisecond,
		MaxBackoff:     5 * time.Millisecond,
		Multiplier:     2,
	})

	result := bulk.Resolve(context.Background(), "nx.example.com")
	require.NotNil(t, result.Data, "NXDOMAIN is a definitive answer and must be returned")
	require.Equal(t, 1, result.Attempts, "NXDOMAIN must not be retried")
	require.Equal(t, miekgdns.RcodeNameError, result.Data.StatusCodeRaw)
}

func TestBulkResolveAllDedupesInput(t *testing.T) {
	server := startTestDNSServer(t, aRecordHandler("10.0.0.1", "10.0.0.1", "10.0.0.1"))
	bulk := newTestBulkResolver(t, []string{"udp:" + server.addr}, RetryPolicy{MaxAttempts: 1})

	hosts := []string{
		"www.example.com",
		"WWW.example.com.",
		" www.example.com ",
		"",
		"mail.example.com",
	}
	results := make(map[string]*BulkResult)
	for result := range bulk.ResolveAll(context.Background(), hosts) {
		_, duplicate := results[result.Host]
		require.False(t, duplicate, "host %s resolved more than once", result.Host)
		results[result.Host] = result
	}
	require.Len(t, results, 2)
	require.Equal(t, []string{"10.0.0.1"}, results["www.example.com"].Data.A, "duplicate A records must be deduplicated")

	stats := bulk.Stats()
	require.Equal(t, uint64(2), stats.Completed)
	require.Equal(t, uint64(0), stats.Failed)
}

func TestDedupeDNSData(t *testing.T) {
	dnsData := &retryabledns.DNSData{
		A:   []string{"1.1.1.1", "2.2.2.2", "1.1.1.1"},
		TXT: []string{"a.txt", "b.txt", "a.txt"},
		SOA: []retryabledns.SOA{
			{Name: "example.com", NS: "ns1.example.com"},
			{Name: "example.com", NS: "ns1.example.com"},
		},
	}
	DedupeDNSData(dnsData)
	require.Equal(t, []string{"1.1.1.1", "2.2.2.2"}, dnsData.A)
	require.Equal(t, []string{"a.txt", "b.txt"}, dnsData.TXT)
	require.Len(t, dnsData.SOA, 1)
}

// TestBulkResolve100K is the 100k-domain performance test: it resolves
// 100,000 unique domains (plus duplicates, to exercise input deduplication)
// against two local resolvers and reports the achieved throughput.
func TestBulkResolve100K(t *testing.T) {
	const totalDomains = 100_000

	serverA := startTestDNSServer(t, aRecordHandler("10.10.0.1", "10.10.0.1"))
	serverB := startTestDNSServer(t, aRecordHandler("10.10.0.2", "10.10.0.2"))

	bulk, err := NewBulkResolver(BulkOptions{
		Resolvers:   []string{"udp:" + serverA.addr, "udp:" + serverB.addr},
		Concurrency: 500,
		Retry: RetryPolicy{
			MaxAttempts:    3,
			InitialBackoff: 10 * time.Millisecond,
			MaxBackoff:     100 * time.Millisecond,
			Multiplier:     2,
		},
		Pool: PoolOptions{Timeout: 2 * time.Second},
	})
	require.NoError(t, err)

	hosts := make([]string, 0, totalDomains+totalDomains/10)
	for i := 0; i < totalDomains; i++ {
		hosts = append(hosts, fmt.Sprintf("host-%06d.perf.example.com", i))
	}
	// 10% duplicates with different casing to verify input deduplication.
	for i := 0; i < totalDomains/10; i++ {
		hosts = append(hosts, fmt.Sprintf("HOST-%06d.perf.example.COM.", i))
	}

	start := time.Now()
	seen := make(map[string]struct{}, totalDomains)
	var failed int
	for result := range bulk.ResolveAll(context.Background(), hosts) {
		if _, duplicate := seen[result.Host]; duplicate {
			t.Fatalf("duplicate result for host %s", result.Host)
		}
		seen[result.Host] = struct{}{}
		if result.Data == nil {
			failed++
			continue
		}
		require.Len(t, result.Data.A, 1, "response records must be deduplicated")
	}
	elapsed := time.Since(start)

	require.Equal(t, totalDomains, len(seen), "every unique domain must produce exactly one result")
	require.Equal(t, 0, failed, "no domain may fail against healthy resolvers")

	stats := bulk.Stats()
	require.Equal(t, uint64(totalDomains), stats.Completed)
	require.GreaterOrEqual(t, stats.Queries, uint64(totalDomains))

	poolStats := bulk.Pool().Stats()
	require.Len(t, poolStats, 2)
	require.Greater(t, poolStats[0].Queries, uint64(0), "both resolvers must be used")
	require.Greater(t, poolStats[1].Queries, uint64(0), "both resolvers must be used")

	qps := float64(totalDomains) / elapsed.Seconds()
	t.Logf("resolved %d domains in %s (%.0f qps, %d queries, %d retries, pool: %+v)",
		totalDomains, elapsed.Round(time.Millisecond), qps, stats.Queries, stats.Retries, poolStats)
	require.Less(t, elapsed, 2*time.Minute, "100k domains must resolve within the time budget")
}

// BenchmarkBulkResolve100K measures bulk resolution throughput on 100k domains.
func BenchmarkBulkResolve100K(b *testing.B) {
	server := startTestDNSServer(b, aRecordHandler("10.10.0.1"))
	bulk, err := NewBulkResolver(BulkOptions{
		Resolvers:   []string{"udp:" + server.addr},
		Concurrency: 500,
		Retry:       RetryPolicy{MaxAttempts: 1},
		Pool:        PoolOptions{Timeout: 2 * time.Second},
	})
	require.NoError(b, err)
	hosts := make([]string, 100_000)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("bench-%06d.example.com", i)
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		for range bulk.ResolveAll(context.Background(), hosts) {
		}
	}
}
