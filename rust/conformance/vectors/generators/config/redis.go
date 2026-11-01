//go:build silo_config_vectors

package main

import (
	redisv9 "github.com/redis/go-redis/v9"

	"github.com/Silo-Server/silo-server/internal/config"
)

type redisTLS struct {
	ServerName         string
	InsecureSkipVerify bool
}

// The option fields a URL can set, in the order the Rust struct serializes them.
type redisOptions struct {
	Network               string
	Addr                  string
	ClientName            string
	Protocol              int
	Username              string
	Password              string
	DB                    int
	MaxRetries            int
	MinRetryBackoff       int64
	MaxRetryBackoff       int64
	DialTimeout           int64
	ReadTimeout           int64
	WriteTimeout          int64
	PoolFIFO              bool
	PoolSize              int
	MaxConcurrentDials    int
	PoolTimeout           int64
	MinIdleConns          int
	MaxIdleConns          int
	MaxActiveConns        int
	ConnMaxIdleTime       int64
	ConnMaxLifetime       int64
	ConnMaxLifetimeJitter int64
	TLS                   *redisTLS
}

type failoverOptions struct {
	MasterName              string
	SentinelAddrs           []string
	ClientName              string
	SentinelUsername        string
	SentinelPassword        string
	RouteByLatency          bool
	RouteRandomly           bool
	ReplicaOnly             bool
	UseDisconnectedReplicas bool
	Protocol                int
	Username                string
	Password                string
	DB                      int
	MaxRetries              int
	MinRetryBackoff         int64
	MaxRetryBackoff         int64
	DialTimeout             int64
	DialerRetries           int
	DialerRetryTimeout      int64
	ReadTimeout             int64
	WriteTimeout            int64
	ContextTimeoutEnabled   bool
	PoolFIFO                bool
	PoolSize                int
	MaxConcurrentDials      int
	PoolTimeout             int64
	MinIdleConns            int
	MaxIdleConns            int
	MaxActiveConns          int
	ConnMaxIdleTime         int64
	ConnMaxLifetime         int64
	ConnMaxLifetimeJitter   int64
	DisableIdentity         bool
	IdentitySuffix          string
	UnstableResp3           bool
	TLS                     *redisTLS
}

func dumpOptions(o *redisv9.Options) redisOptions {
	out := redisOptions{Network: o.Network, Addr: o.Addr, ClientName: o.ClientName, Protocol: o.Protocol, Username: o.Username, Password: o.Password, DB: o.DB, MaxRetries: o.MaxRetries,
		MinRetryBackoff: int64(o.MinRetryBackoff), MaxRetryBackoff: int64(o.MaxRetryBackoff), DialTimeout: int64(o.DialTimeout), ReadTimeout: int64(o.ReadTimeout), WriteTimeout: int64(o.WriteTimeout),
		PoolFIFO: o.PoolFIFO, PoolSize: o.PoolSize, MaxConcurrentDials: o.MaxConcurrentDials, PoolTimeout: int64(o.PoolTimeout), MinIdleConns: o.MinIdleConns, MaxIdleConns: o.MaxIdleConns, MaxActiveConns: o.MaxActiveConns,
		ConnMaxIdleTime: int64(o.ConnMaxIdleTime), ConnMaxLifetime: int64(o.ConnMaxLifetime), ConnMaxLifetimeJitter: int64(o.ConnMaxLifetimeJitter)}
	if o.TLSConfig != nil {
		out.TLS = &redisTLS{o.TLSConfig.ServerName, o.TLSConfig.InsecureSkipVerify}
	}
	return out
}

func dumpFailover(o *redisv9.FailoverOptions) failoverOptions {
	out := failoverOptions{MasterName: o.MasterName, SentinelAddrs: o.SentinelAddrs, ClientName: o.ClientName, SentinelUsername: o.SentinelUsername, SentinelPassword: o.SentinelPassword,
		RouteByLatency: o.RouteByLatency, RouteRandomly: o.RouteRandomly, ReplicaOnly: o.ReplicaOnly, UseDisconnectedReplicas: o.UseDisconnectedReplicas, Protocol: o.Protocol, Username: o.Username, Password: o.Password, DB: o.DB,
		MaxRetries: o.MaxRetries, MinRetryBackoff: int64(o.MinRetryBackoff), MaxRetryBackoff: int64(o.MaxRetryBackoff), DialTimeout: int64(o.DialTimeout), DialerRetries: o.DialerRetries, DialerRetryTimeout: int64(o.DialerRetryTimeout),
		ReadTimeout: int64(o.ReadTimeout), WriteTimeout: int64(o.WriteTimeout), ContextTimeoutEnabled: o.ContextTimeoutEnabled, PoolFIFO: o.PoolFIFO, PoolSize: o.PoolSize, MaxConcurrentDials: o.MaxConcurrentDials, PoolTimeout: int64(o.PoolTimeout),
		MinIdleConns: o.MinIdleConns, MaxIdleConns: o.MaxIdleConns, MaxActiveConns: o.MaxActiveConns, ConnMaxIdleTime: int64(o.ConnMaxIdleTime), ConnMaxLifetime: int64(o.ConnMaxLifetime), ConnMaxLifetimeJitter: int64(o.ConnMaxLifetimeJitter),
		DisableIdentity: o.DisableIdentity, IdentitySuffix: o.IdentitySuffix, UnstableResp3: o.UnstableResp3}
	if o.TLSConfig != nil {
		out.TLS = &redisTLS{o.TLSConfig.ServerName, o.TLSConfig.InsecureSkipVerify}
	}
	return out
}

type redisVector struct {
	URL       string    `json:"url"`
	Single    string    `json:"single,omitempty"`
	Failover  string    `json:"failover,omitempty"`
	Error     string    `json:"error,omitempty"`
	Normalize result    `json:"normalize"`
	DB        []redisDB `json:"db"`
}

type redisDB struct {
	DB        string `json:"db"`
	Database  *int   `json:"database"`
	Options   string `json:"options,omitempty"`
	Bootstrap string `json:"bootstrap"`
}

func writeRedisVectors() {
	urls := []string{
		"", " ", "  redis://user:secret@redis.example:6380/3\n", "redis://redis.example:6379?read_timeout=0", "redis://localhost", "redis://", "rediss://h:1/2?skip_verify=true", "rediss://h", "redis://h/1/2", "redis://h/x", "redis://h?db=4", "redis://h/2?db=x", "unix:///tmp/r.sock", "unix:///tmp/r.sock?db=3", "unix://", "unix:///tmp/r.sock?db=x", "http://localhost:6379",
		"redis://localhost:6379?unknown=1", "redis://localhost:6379?a=1&b=2", "redis://localhost:6379?pool_size=-1", "redis://localhost:6379?pool_size=x", "redis://localhost:6379?pool_size=3&min_idle_conns=1&max_idle_conns=2&max_active_conns=4&max_concurrent_dials=5", "redis://h?protocol=2&client_name=c&max_retries=1&min_retry_backoff=1s&max_retry_backoff=2&dial_timeout=3s&read_timeout=-1&write_timeout=0&pool_fifo=true&pool_timeout=9s&idle_timeout=1m&max_conn_age=2m",
		"redis://h?conn_max_idle_time=1s&idle_timeout=2s&conn_max_lifetime=3s&max_conn_age=4s", "redis://h?conn_max_lifetime=5s&conn_max_lifetime_jitter=9s", "redis://h?conn_max_lifetime_jitter=1s", "redis://h?pool_fifo=maybe", "redis://h?dial_timeout=soon", "redis://h?skip_verify=true", "redis://[::1]:6379/1", "redis://[::1]/1", "redis://::1/1", "redis://p%40ss:w%2Frd@h:1", "redis://u:p#ss@h:1", "redis://u:p/ss@h:1", "redis://u:p?ss@h:1/2", "redis://h:port", "redis://h:1:2", "redis://h/-1", "redis://h?db=-3", "redis://h?db=99",
		"redis://watcher:sentinel-secret@sentinel-1:26379/2?master_name=mymaster&addr=sentinel-2:26379&addr=sentinel-3:26379&username=silo&password=redis-secret", "redis://sentinel-1:26379?master_name=mymaster&dial_timeout=2s", "redis://sentinel-1:26379?master_name=mymaster&read_timeout=4s", "redis://sentinel-1:26379?master_name=mymaster&read_timeout=0s&dial_timeout=0s", "redis://[2001:db8::1]:26379?master%5Fname=mymaster",
		"redis://sentinel-1:26379?master_name=", "redis://sentinel-1:26379?master_name=%20", "redis://sentinel-1:26379?master_name=mymaster&addr=sentinel-2", "redis://sentinel-1:26379?master_name=mymaster&unknown=1", "redis://sentinel-1?master_name=mymaster", "redis://sentinel-1:?master_name=mymaster", "redis://:26379?master_name=mymaster", "redis://sentinel-1:26379,sentinel-2:26379?master_name=mymaster", "redis://2001:db8::1:26379?master_name=mymaster",
		"redis://sentinel-1:26379?master_name=mymaster&route_by_latency=true", "redis://sentinel-1:26379?master_name=mymaster&route_randomly=true", "redis://sentinel-1:26379?master_name=mymaster&replica_only=true", "redis://sentinel-1:26379?master_name=mymaster&use_disconnected_replicas=true", "redis://sentinel-1:26379?master_name=mymaster;addr=sentinel-2:26379", "redis://sentinel-1:26379?password=p;ss&master_name=mymaster", "redis://sentinel-1:26379?password=p;ss&master%5Fname=mymaster", "redis://sentinel-1:26379?master%5Fname=mymaster;addr=sentinel-2:26379", "redis://sentinel-1:26379?addr=sentinel-2:26379;master%5Fname=mymaster", "redis://sentinel-1:26379?master%5Fname=my%zzmaster", "redis://sentinel-1:26379?%6Daster_name=mymaster;x",
		"redis://sentinel-1:26379?master_name=mymaster&password=p#ss&addr=sentinel-2:26379", "redis://sentinel-1:26379?password=p#ss&master_name=mymaster", "redis://sentinel-1:26379?dial_timeout=5s#&master_name=mymaster", "redis://sentinel-1:26379?master_name=mymaster&read_timeout=0", "redis://sentinel-1:26379?master_name=mymaster&read_timeout=-1s", "redis://sentinel-1:26379?master_name=mymaster&dial_timeout=0", "redis://sentinel-1:26379?master_name=mymaster&dial_timeout=-1s", "redis://sentinel-1:26379?master_name=mymaster&password=p+ss", "redis://sentinel-1:26379?master_name=mymaster&pool_size=-1",
		"rediss://u:p@sentinel-1:26379/3?master_name=m&skip_verify=true&db=7&client_name=c&protocol=3&max_retries=1&min_retry_backoff=1&max_retry_backoff=2&dialer_retries=2&dialer_retry_timeout=1s&write_timeout=1s&context_timeout_enabled=1&pool_fifo=0&pool_size=2&max_concurrent_dials=3&min_idle_conns=1&max_idle_conns=2&max_active_conns=3&conn_max_lifetime=1s&conn_max_lifetime_jitter=2s&conn_max_idle_time=1s&pool_timeout=1s&disableIdentity=true&identitySuffix=x&unstable_resp3=true",
		"redis://h?x=%zz", "redis://h?x=1;y=2", "redis://h#frag", "redis://h?a=1#master_name", "http://sentinel:1?master_name=m", "redis://s:1/1/2?master_name=m", "redis://s:1/x?master_name=m", "redis://s:1?master_name=m&db=x", "redis://s:1?master_name=m&protocol=x", "redis://s:1?master_name=m&route_randomly=x",
		"redis://%zz", "redis://h\x7f", ":bad", "redis://u@h:1", "redis://:p@h:1", "redis://u:@h:1",
	}
	out := make([]redisVector, 0, len(urls))
	for _, u := range urls {
		vec := redisVector{URL: u}
		o, f, err := config.ParseRedisURL(u)
		switch {
		case err != nil:
			vec.Error = err.Error()
		case f != nil:
			vec.Failover = goJSON(dumpFailover(f))
		default:
			vec.Single = goJSON(dumpOptions(o))
		}
		n, nerr := config.NormalizeRedisURL(u)
		vec.Normalize = errResult(n, nerr)
		for _, db := range []string{"", " 5 ", "x", "-1"} {
			cfg := config.RedisConfig{URL: u, DB: db}
			row := redisDB{DB: db, Bootstrap: goJSON(cfg.WithBootstrapURL("redis://boot:1"))}
			if d, ok := cfg.Database(); ok {
				row.Database = &d
			}
			if opt, fo, oerr := cfg.Options(); oerr != nil {
				row.Options = "error: " + oerr.Error()
			} else if fo != nil {
				row.Options = goJSON(dumpFailover(fo))
			} else {
				row.Options = goJSON(dumpOptions(opt))
			}
			vec.DB = append(vec.DB, row)
		}
		out = append(out, vec)
	}
	dbs := map[string]result{}
	for _, v := range []string{"", " ", "0", " 3 ", "-1", "x", "1.5", "+2", "99999999999999999999"} {
		n, err := config.NormalizeRedisDB(v)
		dbs[v] = errResult(n, err)
	}
	write("redis_url.json", map[string]any{"urls": out, "normalize_db": dbs})
}
