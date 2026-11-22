package dnsx

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	miekgdns "github.com/miekg/dns"
	retryabledns "github.com/projectdiscovery/retryabledns"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

// ErrBulkRetriesExceeded is returned when a host could not be resolved
// within the attempts allowed by the retry policy.
var ErrBulkRetriesExceeded = errors.New("bulk resolve: retries exceeded")

// RetryPolicy describes how failed lookups are retried. Each attempt uses
// the next resolver from the pool, so retries naturally rotate across
// resolvers. The delay before retry N (1-based) grows exponentially from
// InitialBackoff by Multiplier and is capped at MaxBackoff.
type RetryPolicy struct {
	MaxAttempts    int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	Multiplier     float64
}

// DefaultRetryPolicy is the default retry strategy for bulk resolution.
var DefaultRetryPolicy = RetryPolicy{
	MaxAttempts:    3,
	InitialBackoff: 100 * time.Millisecond,
	MaxBackoff:     2 * time.Second,
	Multiplier:     2,
}

func (p RetryPolicy) withDefaults() RetryPolicy {
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = DefaultRetryPolicy.MaxAttempts
	}
	if p.InitialBackoff <= 0 {
		p.InitialBackoff = DefaultRetryPolicy.InitialBackoff
	}
	if p.MaxBackoff <= 0 {
		p.MaxBackoff = DefaultRetryPolicy.MaxBackoff
	}
	if p.Multiplier <= 0 {
		p.Multiplier = DefaultRetryPolicy.Multiplier
	}
	return p
}

// backoff returns the delay before the given retry (1-based).
func (p RetryPolicy) backoff(retry int) time.Duration {
	delay := p.InitialBackoff
	for i := 1; i < retry; i++ {
		delay = time.Duration(float64(delay) * p.Multiplier)
		if delay >= p.MaxBackoff {
			return p.MaxBackoff
		}
	}
	return delay
}

// PoolOptions configures the resolver pool clients.
type PoolOptions struct {
	Timeout   time.Duration
	Proxy     string
	Hostsfile bool
	// MaxConsecutiveFailures marks a resolver as unhealthy after this many
	// consecutive failed queries; it is skipped for FailureCooldown.
	// Zero disables health tracking.
	MaxConsecutiveFailures int
	FailureCooldown        time.Duration
}

func (o PoolOptions) withDefaults() PoolOptions {
	if o.Timeout <= 0 {
		o.Timeout = DefaultOptions.Timeout
	}
	if o.MaxConsecutiveFailures <= 0 {
		o.MaxConsecutiveFailures = 5
	}
	if o.FailureCooldown <= 0 {
		o.FailureCooldown = 5 * time.Second
	}
	return o
}

// ResolverStats is a snapshot of per-resolver counters.
type ResolverStats struct {
	Resolver string
	Queries  uint64
	Failures uint64
}

type pooledResolver struct {
	addr   string
	client *retryabledns.Client

	queries            atomic.Uint64
	failures           atomic.Uint64
	consecutiveFailure atomic.Int64
	lastFailureNano    atomic.Int64
}

// ResolverPool is a round-robin pool of DNS resolvers. Each resolver gets a
// dedicated retryabledns client configured for a single attempt, so the
// retry policy lives in the BulkResolver and rotates across pool members.
type ResolverPool struct {
	resolvers []*pooledResolver
	index     atomic.Uint64
	options   PoolOptions
}

// NewResolverPool creates a pool from resolver addresses (e.g. "udp:1.1.1.1:53").
func NewResolverPool(resolvers []string, options PoolOptions) (*ResolverPool, error) {
	if len(resolvers) == 0 {
		return nil, errors.New("resolver pool requires at least one resolver")
	}
	options = options.withDefaults()
	pool := &ResolverPool{options: options}
	seen := make(map[string]struct{}, len(resolvers))
	for _, addr := range resolvers {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		client, err := retryabledns.NewWithOptions(retryabledns.Options{
			BaseResolvers: []string{addr},
			MaxRetries:    1,
			Timeout:       options.Timeout,
			Hostsfile:     options.Hostsfile,
			Proxy:         options.Proxy,
			// NOERROR and NXDOMAIN are definitive answers; anything else
			// (SERVFAIL, REFUSED, ...) is left to the bulk retry policy.
			ExitOnStatusCodes: []int{miekgdns.RcodeSuccess, miekgdns.RcodeNameError},
		})
		if err != nil {
			return nil, err
		}
		client.TCPFallback = true
		pool.resolvers = append(pool.resolvers, &pooledResolver{addr: addr, client: client})
	}
	if len(pool.resolvers) == 0 {
		return nil, errors.New("resolver pool requires at least one valid resolver")
	}
	return pool, nil
}

// Size returns the number of resolvers in the pool.
func (p *ResolverPool) Size() int {
	return len(p.resolvers)
}

// Stats returns a snapshot of the per-resolver counters.
func (p *ResolverPool) Stats() []ResolverStats {
	stats := make([]ResolverStats, 0, len(p.resolvers))
	for _, r := range p.resolvers {
		stats = append(stats, ResolverStats{
			Resolver: r.addr,
			Queries:  r.queries.Load(),
			Failures: r.failures.Load(),
		})
	}
	return stats
}

// next returns the next healthy resolver in round-robin order. Resolvers in
// failure cooldown are skipped; if all of them are cooling down, plain
// round-robin is used as a fallback.
func (p *ResolverPool) next() *pooledResolver {
	n := uint64(len(p.resolvers))
	start := p.index.Add(1)
	for i := uint64(0); i < n; i++ {
		r := p.resolvers[(start+i)%n]
		if r.healthy(p.options) {
			return r
		}
	}
	return p.resolvers[start%n]
}

func (r *pooledResolver) healthy(options PoolOptions) bool {
	if r.consecutiveFailure.Load() < int64(options.MaxConsecutiveFailures) {
		return true
	}
	last := time.Unix(0, r.lastFailureNano.Load())
	return time.Since(last) > options.FailureCooldown
}

// report records the outcome of a query against the resolver.
func (r *pooledResolver) report(failed bool) {
	r.queries.Add(1)
	if failed {
		r.failures.Add(1)
		r.consecutiveFailure.Add(1)
		r.lastFailureNano.Store(time.Now().UnixNano())
		return
	}
	r.consecutiveFailure.Store(0)
}

// BulkOptions configures a BulkResolver.
type BulkOptions struct {
	Resolvers     []string
	QuestionTypes []uint16
	Concurrency   int
	Retry         RetryPolicy
	Pool          PoolOptions
}

// BulkStats is a snapshot of the bulk resolver counters.
type BulkStats struct {
	Completed uint64
	Failed    uint64
	Queries   uint64
	Retries   uint64
}

// BulkResult is the outcome of resolving a single host.
type BulkResult struct {
	Host     string
	Data     *retryabledns.DNSData
	Err      error
	Attempts int
}

// BulkResolver resolves large batches of hosts through a resolver pool,
// applying a retry policy per host and deduplicating both the input hosts
// and the records of every response.
type BulkResolver struct {
	pool          *ResolverPool
	questionTypes []uint16
	concurrency   int
	retry         RetryPolicy

	completed atomic.Uint64
	failed    atomic.Uint64
	queries   atomic.Uint64
	retries   atomic.Uint64
}

// NewBulkResolver creates a bulk resolver from the given options.
func NewBulkResolver(options BulkOptions) (*BulkResolver, error) {
	pool, err := NewResolverPool(options.Resolvers, options.Pool)
	if err != nil {
		return nil, err
	}
	questionTypes := options.QuestionTypes
	if len(questionTypes) == 0 {
		questionTypes = []uint16{miekgdns.TypeA}
	}
	concurrency := options.Concurrency
	if concurrency <= 0 {
		concurrency = 100
	}
	return &BulkResolver{
		pool:          pool,
		questionTypes: questionTypes,
		concurrency:   concurrency,
		retry:         options.Retry.withDefaults(),
	}, nil
}

// Pool returns the underlying resolver pool.
func (b *BulkResolver) Pool() *ResolverPool {
	return b.pool
}

// Stats returns a snapshot of the bulk resolver counters.
func (b *BulkResolver) Stats() BulkStats {
	return BulkStats{
		Completed: b.completed.Load(),
		Failed:    b.failed.Load(),
		Queries:   b.queries.Load(),
		Retries:   b.retries.Load(),
	}
}

// Resolve resolves a single host, retrying according to the retry policy.
// Every attempt uses the next resolver from the pool.
func (b *BulkResolver) Resolve(ctx context.Context, host string) *BulkResult {
	result := &BulkResult{Host: host}
	for attempt := 1; attempt <= b.retry.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			result.Err = err
			return result
		}
		resolver := b.pool.next()
		data, err := resolver.client.QueryMultiple(host, b.questionTypes)
		b.queries.Add(1)
		failed := !isDefinitive(data)
		resolver.report(failed)
		result.Attempts = attempt
		if !failed {
			DedupeDNSData(data)
			result.Data = data
			result.Err = err
			return result
		}
		result.Err = err
		if attempt < b.retry.MaxAttempts {
			b.retries.Add(1)
			select {
			case <-ctx.Done():
				result.Err = ctx.Err()
				return result
			case <-time.After(b.retry.backoff(attempt)):
			}
		}
	}
	if result.Err == nil {
		result.Err = ErrBulkRetriesExceeded
	}
	return result
}

// ResolveAll resolves a batch of hosts concurrently and streams the results.
// Hosts are normalized (trimmed, lowercased, trailing dot removed) and
// deduplicated before resolution, so every unique host is resolved exactly
// once. The returned channel is closed when all hosts have been processed
// or the context is cancelled.
func (b *BulkResolver) ResolveAll(ctx context.Context, hosts []string) <-chan *BulkResult {
	out := make(chan *BulkResult)
	go func() {
		defer close(out)

		jobs := make(chan string)
		var wg sync.WaitGroup
		for i := 0; i < b.concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for host := range jobs {
					result := b.Resolve(ctx, host)
					if result.Data != nil {
						b.completed.Add(1)
					} else {
						b.failed.Add(1)
					}
					select {
					case out <- result:
					case <-ctx.Done():
						return
					}
				}
			}()
		}

		seen := make(map[string]struct{}, len(hosts))
	feed:
		for _, host := range hosts {
			normalized := NormalizeHost(host)
			if normalized == "" {
				continue
			}
			if _, ok := seen[normalized]; ok {
				continue
			}
			seen[normalized] = struct{}{}
			select {
			case jobs <- normalized:
			case <-ctx.Done():
				break feed
			}
		}
		close(jobs)
		wg.Wait()
	}()
	return out
}

// NormalizeHost normalizes a host for deduplication: it trims whitespace,
// lowercases and strips the trailing dot.
func NormalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

// isDefinitive reports whether a response is a final answer that should not
// be retried: a parsable response with a definitive rcode (NOERROR or
// NXDOMAIN, per the pool's ExitOnStatusCodes).
func isDefinitive(data *retryabledns.DNSData) bool {
	if data == nil || data.Host == "" || data.Timestamp.IsZero() {
		return false
	}
	switch data.StatusCodeRaw {
	case miekgdns.RcodeSuccess, miekgdns.RcodeNameError:
		return true
	}
	return false
}

// DedupeDNSData removes duplicate records from every record slice of the
// response, preserving the original order.
func DedupeDNSData(data *retryabledns.DNSData) {
	if data == nil {
		return
	}
	data.Resolver = sliceutil.Dedupe(data.Resolver)
	data.A = sliceutil.Dedupe(data.A)
	data.AAAA = sliceutil.Dedupe(data.AAAA)
	data.CNAME = sliceutil.Dedupe(data.CNAME)
	data.MX = sliceutil.Dedupe(data.MX)
	data.PTR = sliceutil.Dedupe(data.PTR)
	data.NS = sliceutil.Dedupe(data.NS)
	data.TXT = sliceutil.Dedupe(data.TXT)
	data.SRV = sliceutil.Dedupe(data.SRV)
	data.CAA = sliceutil.Dedupe(data.CAA)
	data.AllRecords = sliceutil.Dedupe(data.AllRecords)
	data.SOA = dedupeSOARecords(data.SOA)
}

func dedupeSOARecords(records []retryabledns.SOA) []retryabledns.SOA {
	if len(records) <= 1 {
		return records
	}
	seen := make(map[retryabledns.SOA]struct{}, len(records))
	result := make([]retryabledns.SOA, 0, len(records))
	for _, record := range records {
		if _, ok := seen[record]; ok {
			continue
		}
		seen[record] = struct{}{}
		result = append(result, record)
	}
	return result
}
