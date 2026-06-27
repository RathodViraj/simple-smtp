package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"smtp-server/db"
	"strconv"
	"strings"

	"github.com/redis/go-redis/v9"
)

var (
	rdb *redis.Client
	ctx = context.Background()
)

type POP3Session struct {
	conn          net.Conn
	username      string
	authenticated bool
	deleted       map[string]bool
}

func main() {
	var err error
	rdb, err = db.ConnectRedis()
	if err != nil {
		log.Fatal(err)
	}

	listener, err := net.Listen("tcp", ":1100")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("POP3 server running on :1100")

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handlePOP3(conn)
	}
}

func handlePOP3(conn net.Conn) {
	defer conn.Close()

	session := &POP3Session{
		conn:    conn,
		deleted: make(map[string]bool),
	}

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	writer.WriteString("+OK POP3 server ready\r\n")
	writer.Flush()

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		line = strings.TrimSpace(line)
		parts := strings.Split(line, " ")

		switch strings.ToUpper(parts[0]) {

		case "USER":
			if len(parts) < 2 {
				writer.WriteString("-ERR Missing username\r\n")
				break
			}
			session.username = parts[1]
			writer.WriteString("+OK User accepted\r\n")

		case "PASS":
			if session.username == "" {
				writer.WriteString("-ERR USER required first\r\n")
				break
			}

			if authenticate(session.username, parts[1]) {
				session.authenticated = true
				writer.WriteString("+OK Mailbox locked and ready\r\n")
			} else {
				writer.WriteString("-ERR Invalid credentials\r\n")
			}

		case "LIST":
			if !session.authenticated {
				writer.WriteString("-ERR Not authenticated\r\n")
				break
			}

			keys, _ := rdb.Keys(ctx, "mailbox:"+session.username+":*").Result()

			writer.WriteString(fmt.Sprintf("+OK %d messages\r\n", len(keys)))

			for i, key := range keys {
				if session.deleted[key] {
					continue
				}
				msg, _ := rdb.HGet(ctx, key, "data").Result()
				writer.WriteString(fmt.Sprintf("%d %d\r\n", i+1, len(msg)))
			}

			writer.WriteString(".\r\n")

		case "RETR":
			if !session.authenticated {
				writer.WriteString("-ERR Not authenticated\r\n")
				break
			}
			if len(parts) < 2 {
				writer.WriteString("-ERR Missing message id\r\n")
				break
			}

			id, _ := strconv.Atoi(parts[1])
			keys, _ := rdb.Keys(ctx, "mailbox:"+session.username+":*").Result()

			if id <= 0 || id > len(keys) {
				writer.WriteString("-ERR No such message\r\n")
				break
			}

			key := keys[id-1]
			msg, _ := rdb.HGet(ctx, key, "data").Result()

			writer.WriteString("+OK Message follows\r\n")
			writer.WriteString(msg + "\r\n.\r\n")

		case "DELE":
			if !session.authenticated {
				writer.WriteString("-ERR Not authenticated\r\n")
				break
			}
			id, _ := strconv.Atoi(parts[1])
			keys, _ := rdb.Keys(ctx, "mailbox:"+session.username+":*").Result()

			if id <= 0 || id > len(keys) {
				writer.WriteString("-ERR No such message\r\n")
				break
			}

			key := keys[id-1]
			session.deleted[key] = true
			writer.WriteString("+OK Message marked deleted\r\n")

		case "QUIT":
			if session.authenticated {
				for key := range session.deleted {
					rdb.Del(ctx, key)
				}
			}
			writer.WriteString("+OK Goodbye\r\n")
			writer.Flush()
			return

		default:
			writer.WriteString("-ERR Unknown command\r\n")
		}

		writer.Flush()
	}
}

func authenticate(username, password string) bool {
	stored, err := rdb.HGet(ctx, "user:"+username, "password").Result()
	if err != nil {
		return false
	}
	return password == stored
}
