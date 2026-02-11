package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"smtp-server/db"
	"smtp-server/middleware"
	"sort"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sony/sonyflake/v2"
	"golang.org/x/crypto/bcrypt"
)

var (
	IDGen        *sonyflake.Sonyflake
	rl           *middleware.RateLimiter
	auth         *middleware.Auth
	LocalDomains = map[string]bool{
		"myserver.local": true, // placeholder
	}
	rdb *redis.Client
)

const startEpochInMilli = 1767225600000

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
	var err error
	rdb, err = db.ConnectRedis()
	if err != nil {
		log.Fatal(err)
	}

	IDGen, err = sonyflake.New(sonyflake.Settings{
		StartTime: time.UnixMilli(startEpochInMilli),
	})
	if err != nil {
		log.Fatal(err)
	}

	rl = middleware.NewRateLimit(rdb, 20, 5, 5*time.Minute)
	auth = middleware.SetupAuth(rdb, 5, 10*time.Second)

	lis, err := net.Listen("tcp", ":8000")
	if err != nil {
		log.Fatal(err)
	}
	defer lis.Close()

	log.Println("listening on port 8000")

	go SaveMailWorker()

	for {
		conn, err := lis.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	session := &SMTPSession{
		conn: conn,
	}

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	writeAndFlush(writer, "220 SimpleSMTP ready\r\n")

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
			host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			ip := net.ParseIP(host)

			writeAndFlush(writer, "334 VXNlcm5hbWU6\r\n")

			userLine, _ := reader.ReadString('\n')
			userNameBytes, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(userLine))
			username := string(userNameBytes)

			if !rl.Validate(username, net.IP(ip)) {
				writeAndFlush(writer, "454 Too many login attempts\r\n")
				continue
			}
			if auth.CheckLock(username) {
				writeAndFlush(writer, "535 Account temporarily locked\r\n")
				continue
			}

			writeAndFlush(writer, "334 UGFzc3dvcmQ6\r\n")

			passLine, _ := reader.ReadString('\n')

			passwordBytes, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(passLine))
			password := string(passwordBytes)

			dbHashPass, err := rdb.HGet(
				context.Background(),
				"user:"+username,
				"password",
			).Result()

			if err == redis.Nil {
				auth.IncreaseFails(username)
				writeAndFlush(writer, "535 Authentication failed\r\n")
				continue
			}
			if err != nil {
				writeAndFlush(writer, "451 Local error\r\n")
				continue
			}

			err = bcrypt.CompareHashAndPassword(
				[]byte(dbHashPass),
				[]byte(password),
			)
			if err != nil {
				auth.IncreaseFails(username)
				writeAndFlush(writer, "535 Authentication failed\r\n")
			} else {
				session.authenticated = true
				session.state = StateInit
				session.userName = username
				rdb.Del(context.Background(), fmt.Sprintf("auth:fail:user:%s", username))
				writeAndFlush(writer, "235 Authentication successful\r\n")
			}

		case strings.HasPrefix(line, "HELO"):
			if !session.validateSession(StateInit, writer) {
				continue
			}
			session.state = StateHelo
			writeAndFlush(writer, "250 Hello\r\n")

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
				writeAndFlush(writer, "535 Authentication failed\r\n")
				continue
			}
			if err != nil {
				writeAndFlush(writer, "451 Local error\r\n")
				continue
			}
			addr := strings.TrimSpace(line[len("MAIL FROM:"):])
			addr = strings.Trim(addr, "<>")
			if dbUserEmail != addr {
				writeAndFlush(writer, "535 Authentication failed\r\n")
				continue
			}

			session.state = StateMail
			session.mailFrom = line
			writeAndFlush(writer, "250 OK\r\n")

		case strings.HasPrefix(line, "RCPT TO:"):
			if !session.validateSession(StateMail, writer) {
				continue
			}
			session.state = StateRcpt
			session.rcpt = line
			writeAndFlush(writer, "250 OK\r\n")

		case line == "DATA":
			if !session.validateSession(StateRcpt, writer) {
				continue
			}
			session.state = StateData

			writeAndFlush(writer, "354 End data with <CR><LF>.<CR><LF>\r\n")

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
				writeAndFlush(writer, "451 Local error in processing\r\n")
				continue
			}

			msg := map[string]any{
				"id":       id,
				"username": session.userName,
				"from":     session.mailFrom,
				"to":       session.rcpt,
				"data":     session.data,
				"time":     time.Now().Unix(),
				"retry":    0,
			}

			msgJSON, err := json.Marshal(msg)
			if err != nil {
				writeAndFlush(writer, "451 Local error in processing\r\n")
				continue
			}

			err = rdb.LPush(context.Background(), "mail_queue", msgJSON).Err()
			if err != nil {
				writeAndFlush(writer, "451 Queue error\r\n")
				continue
			}

			writeAndFlush(writer, "250 Message accepted\r\n")

			session.Reset()

		case line == "RSET":
			session.Reset()
			writeAndFlush(writer, "250 OK\r\n")
			continue

		case line == "QUIT":
			writeAndFlush(writer, "221 Bye\r\n")
			return

		default:
			writeAndFlush(writer, "500 Syntax error, command unrecognized\r\n")
		}
	}
}

func (s *SMTPSession) validateSession(valid SessionState, w *bufio.Writer) bool {
	if !s.authenticated {
		writeAndFlush(w, "530 Authentication required\r\n")
		return false
	}

	if s.state != valid {
		writeAndFlush(w, "503 Bad sequence of commands\r\n")
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

func getDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}

	return parts[1]
}

func lookupMX(domain string) (string, error) {
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return "", err
	}

	sort.Slice(mxRecords, func(i, j int) bool {
		return mxRecords[i].Pref < mxRecords[j].Pref
	})

	return strings.TrimSuffix(mxRecords[0].Host, "."), nil
}

func SaveMailWorker() {
	for {
		res, err := rdb.BRPop(context.Background(), 0, "mail_queue").Result()
		if err != nil {
			log.Println("Error fetching from queue:", err)
			continue
		}

		var msg map[string]any
		err = json.Unmarshal([]byte(res[1]), &msg)
		if err != nil {
			log.Println("Error unmarshaling message:", err)
			continue
		}

		to := msg["to"].(string)
		domain := getDomain(to)

		if LocalDomains[domain] {
			err := rdb.HSet(
				context.Background(),
				fmt.Sprintf("mailbox:%s:%s", msg["username"], msg["id"]),
				msg,
			).Err()
			if err != nil {
				go AddToRetry(msg, err, 3)
				continue
			}
		} else {
			mxHost, err := lookupMX(domain)
			if err != nil {
				go AddToRetry(msg, err, 2)
				continue
			}

			log.Println("Message saved successfully:", msg["id"])
			err = SendSMTP(mxHost+":25", msg["from"].(string), msg["to"].(string), msg["data"].(string))
			if err != nil {
				go AddToRetry(msg, err, 3)
				continue
			}
		}

		err = rdb.HSet(
			context.Background(),
			"mail:"+fmt.Sprint(msg["id"]),
			map[string]any{
				"from":     msg["from"],
				"to":       msg["to"],
				"username": msg["username"],
				"data":     msg["data"],
				"time":     time.Now().Unix(),
				"retry":    msg["retry"],
			},
		).Err()
		if err != nil {
			go AddToRetry(msg, err, 1)
		}
	}
}

func AddToRetry(msg map[string]any, err error, nextAttempt int) {
	msg["error"] = err.Error()
	tries := 0
	if r, ok := msg["retry"].(float64); ok {
		tries = int(r)
	}
	tries++
	if tries > 5 {
		log.Printf("Droping mail. Last error: %s", err.Error())
		msgJSON, _ := json.Marshal(msg)
		rdb.RPush(context.Background(), "failed_mail_queue", msgJSON)
		return
	}
	msg["retry"] = tries
	msgJSON, _ := json.Marshal(msg)
	rdb.ZAdd(context.Background(), "mail_retry_queue", redis.Z{
		Score:  float64(nextAttempt),
		Member: msgJSON,
	})
	log.Println("Retrying message save:", err)
}

func schedulerWorker() {
	now := time.Now().Unix()

	msgs, _ := rdb.ZRangeByScore(context.Background(), "mail_retry_queue", &redis.ZRangeBy{
		Min: "0",
		Max: fmt.Sprint(now),
	}).Result()

	for _, m := range msgs {
		rdb.LPush(context.Background(), "mail_queue", m)
		rdb.ZRem(context.Background(), "mail_retry_queue", m)
	}
}

func writeAndFlush(w *bufio.Writer, msg string) {
	w.WriteString(msg)
	w.Flush()
}
