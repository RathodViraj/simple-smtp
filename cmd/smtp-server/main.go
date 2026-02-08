package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"smtp-server/db"
	ratelimit "smtp-server/rate-limit"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sony/sonyflake/v2"
	"golang.org/x/crypto/bcrypt"
)

var (
	IDGen *sonyflake.Sonyflake
	rl    *ratelimit.RateLimiter
)

const startEpcohInMili = 1767225600000

type SessionState int

const (
	StateInit SessionState = iota
	StateHelo
	StateMail
	StateRcpt
	StateData
)

type SMTPSession struct {
	conn          net.Conn
	state         SessionState
	userName      string
	mailFrom      string
	rcpt          string
	data          string
	authenticated bool
}

func main() {
	rdb, err := db.ConnectRedis()
	if err != nil {
		log.Fatal(err)
	}

	IDGen, err = sonyflake.New(sonyflake.Settings{
		StartTime: time.UnixMilli(startEpcohInMili),
	})

	lis, err := net.Listen("tcp", ":8000")
	if err != nil {
		log.Fatal(err)
	}
	defer lis.Close()

	log.Println("litsing on port 8080")

	for {
		conn, err := lis.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handelConnection(conn, rdb)
	}
}

func handelConnection(conn net.Conn, rdb *redis.Client) {
	defer conn.Close()

	session := &SMTPSession{
		conn:  conn,
		state: StateInit,
	}

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	writer.WriteString("220 SimpleSMTP ready\r\n")
	writer.Flush()

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Println(err)
			conn.Write([]byte("451 server error"))
			return
		}

		line = strings.TrimSpace(line)
		log.Println(line)

		switch {
		case strings.HasPrefix(line, "AUTH LOGIN"):
			writer.WriteString("334 VXNlcm5hbWU6\r\n")
			writer.Flush()

			userLine, _ := reader.ReadString('\n')
			userNameBytes, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(userLine))
			username := string(userNameBytes)
			if !rl.Validate(username) {
				writer.WriteString("454 Too many login attempts\r\n")
				writer.Flush()
				continue
			}

			passLine, _ := reader.ReadString('\n')
			passwordBytes, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(passLine))
			password := string(passwordBytes)

			dbHashPass, err := rdb.HGet(
				context.Background(),
				"user:"+username,
				"password",
			).Result()

			if err == redis.Nil {
				writer.WriteString("535 Authentication failed\r\n")
				writer.Flush()
				continue
			}
			if err != nil {
				writer.WriteString("451 Local error\r\n")
				writer.Flush()
				continue
			}

			err = bcrypt.CompareHashAndPassword(
				[]byte(dbHashPass),
				[]byte(password),
			)
			if err != nil {
				writer.WriteString("535 Authentication failed\r\n")
			} else {
				session.authenticated = true
				writer.WriteString("235 Authentication successful\r\n")
			}
			writer.Flush()

		case strings.HasPrefix(line, "HELO"):
			if !session.validateSession(StateInit, writer) {
				continue
			}
			session.state = StateHelo
			writer.WriteString("250 Hello\r\n")

		case strings.HasPrefix(line, "MAIL FROM:"):
			if !session.validateSession(StateHelo, writer) {
				continue
			}

			dbUserEmail, err := rdb.HGet(
				context.Background(),
				"user:"+session.userName,
				"email",
			).Result()
			if err == redis.Nil || session.userName == "" {
				writer.WriteString("535 Authentication failed\r\n")
				writer.Flush()
				continue
			}
			if err != nil {
				writer.WriteString("451 Local error\r\n")
				writer.Flush()
				continue
			}
			if dbUserEmail != line {
				writer.WriteString("535 Authentication failed\r\n")
				writer.Flush()
				continue
			}

			session.state = StateMail
			session.mailFrom = line
			writer.WriteString("250 OK\r\n")

		case strings.HasPrefix(line, "RCPT TO:"):
			if !session.validateSession(StateMail, writer) {
				continue
			}
			session.state = StateRcpt
			session.rcpt = line
			writer.WriteString("250 OK\r\n")

		case line == "DATA":
			if !session.validateSession(StateRcpt, writer) {
				continue
			}
			session.state = StateData

			writer.WriteString("354 End data with <CR><LF>.<CR><LF>\r\n")
			writer.Flush()

			var body strings.Builder
			for {
				dl, _ := reader.ReadString('\n')
				dl = strings.TrimSpace(dl)

				if dl == "." {
					break
				}
				body.WriteString(dl + "\n")
			}
			session.data = body.String()

			fmt.Println("MAIL:", session.mailFrom)
			fmt.Println("RCPT:", session.rcpt)
			fmt.Println("DATA:", session.data)

			id, err := IDGen.NextID()
			if err != nil {
				log.Println(err)
				writer.WriteString("451 Local error in processing\r\n")
				writer.Flush()
				continue
			}

			err = rdb.HSet(
				context.Background(),
				"mail:"+strconv.Itoa(int(id)),
				map[string]any{
					"from": session.mailFrom,
					"to":   session.rcpt,
					"data": session.data,
				},
			).Err()
			if err != nil {
				log.Panicln(err)
				writer.WriteString("451 Local error in processing\r\n")
				writer.Flush()
				continue
			}

			writer.WriteString("250 Message accepted\r\n")
			writer.Flush()

			session.Reset()

		case line == "RSET":
			session.Reset()
			writer.WriteString("250 OK\r\n")
			writer.Flush()
			continue

		case line == "QUIT":
			writer.WriteString("221 Bye\r\n")
			writer.Flush()
			return

		default:
			writer.WriteString("250 OK\r\n")
		}

		writer.Flush()
	}
}

func (s *SMTPSession) validateSession(valid SessionState, w *bufio.Writer) bool {
	if !s.authenticated {
		w.WriteString("530 Authentication required\r\n")
		w.Flush()
		return false
	}

	if s.state != valid {
		w.WriteString("503 Bad sequence of commands\r\n")
		w.Flush()
		return false
	}

	return true
}

func (s *SMTPSession) Reset() {
	s.mailFrom = ""
	s.rcpt = ""
	s.data = ""
	s.state = StateHelo
}
