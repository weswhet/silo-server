// Command runtimeinterop is the real-Go side of rust/crates/silo-runtime/tests/go_interop.rs: it takes
// advisory locks through pgx and publishes and subscribes through go-redis, at the versions go.mod
// pins, using internal/cache's Event for the wire JSON.
//
// Commands assume the repository root is the cwd:
//
//	GOTOOLCHAIN=go1.26.10 go build -o <bin> ./rust/conformance/harness/runtimeinterop
//
// Subcommands:
//
//	lock-shared <db> <key>       holds pg_advisory_lock_shared, prints "locked", releases on a stdin line, prints "released"
//	lock-exclusive <db> <key>    the same with pg_advisory_lock
//	lock-try-shared <db> <key>   prints the result of pg_try_advisory_lock_shared
//	redis-publish <addr> <channel> <type> <payload>     publishes and prints the wire JSON
//	redis-subscribe <addr> <channel> <timeout-seconds>  prints "subscribed", then "<type> <payload>" for one event
//	lua-sha1 <text>              prints the SHA1 go-redis's Script computes for text
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"

	"github.com/Silo-Server/silo-server/internal/cache"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		log.Fatal("usage: runtimeinterop <subcommand> ...")
	}
	ctx := context.Background()
	switch os.Args[1] {
	case "lock-shared":
		hold(ctx, "SELECT pg_advisory_lock_shared($1)")
	case "lock-exclusive":
		hold(ctx, "SELECT pg_advisory_lock($1)")
	case "lock-try-shared":
		conn, key := connect(ctx)
		defer conn.Close(ctx)
		var ok bool
		if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock_shared($1)", key).Scan(&ok); err != nil {
			log.Fatal(err)
		}
		fmt.Println(ok)
	case "redis-publish":
		client := redis.NewClient(&redis.Options{Addr: os.Args[2]})
		defer client.Close()
		data, err := json.Marshal(cache.Event{Type: os.Args[4], Payload: os.Args[5]})
		if err != nil {
			log.Fatal(err)
		}
		if err := client.Publish(ctx, os.Args[3], data).Err(); err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(data))
	case "redis-subscribe":
		client := redis.NewClient(&redis.Options{Addr: os.Args[2]})
		defer client.Close()
		pubsub := client.Subscribe(ctx, os.Args[3])
		defer pubsub.Close()
		if _, err := pubsub.Receive(ctx); err != nil {
			log.Fatal(err)
		}
		fmt.Println("subscribed")
		seconds, err := strconv.Atoi(os.Args[4])
		if err != nil {
			log.Fatal(err)
		}
		receiveCtx, cancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
		defer cancel()
		msg, err := pubsub.ReceiveMessage(receiveCtx)
		if err != nil {
			log.Fatal(err)
		}
		var event cache.Event
		if err := json.Unmarshal([]byte(msg.Payload), &event); err != nil {
			log.Fatal(err)
		}
		fmt.Println(event.Type, event.Payload)
	case "lua-sha1":
		fmt.Println(redis.NewScript(os.Args[2]).Hash())
	default:
		log.Fatalf("unknown subcommand %q", os.Args[1])
	}
}

func connect(ctx context.Context) (*pgx.Conn, int64) {
	conn, err := pgx.Connect(ctx, os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	key, err := strconv.ParseInt(os.Args[3], 10, 64)
	if err != nil {
		log.Fatal(err)
	}
	return conn, key
}

func hold(ctx context.Context, sql string) {
	conn, key := connect(ctx)
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, sql, key); err != nil {
		log.Fatal(err)
	}
	fmt.Println("locked")
	// Closing the connection releases the lock, as a crash of the holder would.
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		log.Fatal(err)
	}
	if err := conn.Close(ctx); err != nil {
		log.Fatal(err)
	}
	fmt.Println("released")
}
