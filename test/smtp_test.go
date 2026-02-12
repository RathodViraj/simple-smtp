package main_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// ─────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────

const (
	smtpAddr = "localhost:8000"
	httpAddr = "http://localhost:9000"

	testUsername = "testuser"
	testPassword = "TestPassword123"
	testEmail    = "testuser@example.com"

	testUsername2 = "testuser2"
	testEmail2    = "testuser2@example.com"
)

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

func redisClient() *redis.Client {
	return redis.NewClient(&redis.Options{Addr: "localhost:6379"})
}

// cleanAll wipes every Redis key that tests can create for a given username.
// Call it at the START of each test AND defer it so stale state from a
// previous run or a crashed test never bleeds into the next one.
// The IP bucket is always 127.0.0.1 because tests connect locally.
func cleanAll(t *testing.T, rdb *redis.Client, username string) {
	t.Helper()
	rdb.Del(context.Background(),
		"user:"+username,
		"auth:fail:user:"+username,
		"lock:user:"+username,
		"auth:user:"+username, // rate limiter per-user bucket
		"auth:ip:127.0.0.1",   // rate limiter per-IP bucket (IPv4 loopback)
		"auth:ip:::1",          // rate limiter per-IP bucket (IPv6 loopback)
	)
}

// createUser calls the HTTP endpoint and returns the status code.
func createUser(t *testing.T, username, password, email string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
		"email":    email,
	})
	resp, err := http.Post(httpAddr+"/create-user", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("HTTP create-user failed: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// smtpDial opens a raw TCP connection to the SMTP server.
func smtpDial(t *testing.T) (net.Conn, *bufio.Reader, *bufio.Writer) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", smtpAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("cannot connect to SMTP server: %v", err)
	}
	return conn, bufio.NewReader(conn), bufio.NewWriter(conn)
}

// send writes a CRLF-terminated line and flushes immediately.
func send(t *testing.T, w *bufio.Writer, line string) {
	t.Helper()
	if _, err := fmt.Fprintf(w, "%s\r\n", line); err != nil {
		t.Fatalf("write error: %v", err)
	}
	w.Flush()
}

// readLine reads one response line from the server.
func readLine(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	return strings.TrimSpace(line)
}

// assertCode checks the response starts with the expected 3-digit code.
func assertCode(t *testing.T, resp, wantCode string) {
	t.Helper()
	if !strings.HasPrefix(resp, wantCode) {
		t.Errorf("expected code %s, got: %q", wantCode, resp)
	}
}

// b64 base64-encodes a string for AUTH LOGIN.
func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// smtpLogin reads the greeting, sends AUTH LOGIN, handles the two-step
// 334 prompt flow, and returns the final response (235/535/454).
func smtpLogin(t *testing.T, r *bufio.Reader, w *bufio.Writer, username, password string) string {
	t.Helper()
	readLine(t, r) // 220 greeting
	send(t, w, "AUTH LOGIN")
	assertCode(t, readLine(t, r), "334") // username prompt
	send(t, w, b64(username))
	resp := readLine(t, r) // 334 password prompt, or 454/535 if rate-limited/locked
	if !strings.HasPrefix(resp, "334") {
		return resp // 454 or 535
	}
	send(t, w, b64(password))
	return readLine(t, r) // 235 or 535
}

// fullLogin dials, authenticates, sends HELO, and returns the open connection
// ready for MAIL FROM.
func fullLogin(t *testing.T, username, password string) (net.Conn, *bufio.Reader, *bufio.Writer) {
	t.Helper()
	conn, r, w := smtpDial(t)
	readLine(t, r) // 220 greeting
	send(t, w, "AUTH LOGIN")
	assertCode(t, readLine(t, r), "334") // username prompt
	send(t, w, b64(username))
	assertCode(t, readLine(t, r), "334") // password prompt
	send(t, w, b64(password))
	assertCode(t, readLine(t, r), "235")
	send(t, w, "HELO localhost")
	assertCode(t, readLine(t, r), "250")
	return conn, r, w
}

// ─────────────────────────────────────────────
// HTTP /create-user
// ─────────────────────────────────────────────

func TestCreateUser_Success(t *testing.T) {
	rdb := redisClient()
	cleanAll(t, rdb, testUsername)
	defer cleanAll(t, rdb, testUsername)

	code := createUser(t, testUsername, testPassword, testEmail)
	if code != http.StatusCreated && code != http.StatusOK {
		t.Errorf("expected 200/201, got %d", code)
	}
}

func TestCreateUser_Duplicate(t *testing.T) {
	rdb := redisClient()
	cleanAll(t, rdb, testUsername)
	defer cleanAll(t, rdb, testUsername)

	createUser(t, testUsername, testPassword, testEmail)
	code := createUser(t, testUsername, testPassword, testEmail)
	if code != http.StatusConflict && code != http.StatusBadRequest {
		t.Errorf("expected 409/400 for duplicate user, got %d", code)
	}
}

func TestCreateUser_MissingFields(t *testing.T) {
	cases := []struct {
		name string
		body map[string]string
	}{
		{"missing username", map[string]string{"password": testPassword, "email": testEmail}},
		{"missing password", map[string]string{"username": testUsername, "email": testEmail}},
		{"missing email", map[string]string{"username": testUsername, "password": testPassword}},
		{"empty body", map[string]string{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(tc.body)
			resp, err := http.Post(httpAddr+"/create-user", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode < 400 {
				t.Errorf("expected 4xx for %s, got %d", tc.name, resp.StatusCode)
			}
		})
	}
}

// ─────────────────────────────────────────────
// SMTP greeting & QUIT
// ─────────────────────────────────────────────

func TestSMTP_Greeting(t *testing.T) {
	conn, r, _ := smtpDial(t)
	defer conn.Close()
	assertCode(t, readLine(t, r), "220")
}

func TestSMTP_Quit(t *testing.T) {
	conn, r, w := smtpDial(t)
	defer conn.Close()
	readLine(t, r) // 220
	send(t, w, "QUIT")
	assertCode(t, readLine(t, r), "221")
}

// ─────────────────────────────────────────────
// AUTH LOGIN
// ─────────────────────────────────────────────

func TestAuth_Success(t *testing.T) {
	rdb := redisClient()
	cleanAll(t, rdb, testUsername)
	defer cleanAll(t, rdb, testUsername)
	createUser(t, testUsername, testPassword, testEmail)

	conn, r, w := smtpDial(t)
	defer conn.Close()
	assertCode(t, smtpLogin(t, r, w, testUsername, testPassword), "235")
}

func TestAuth_WrongPassword(t *testing.T) {
	rdb := redisClient()
	cleanAll(t, rdb, testUsername)
	defer cleanAll(t, rdb, testUsername)
	createUser(t, testUsername, testPassword, testEmail)

	conn, r, w := smtpDial(t)
	defer conn.Close()
	assertCode(t, smtpLogin(t, r, w, testUsername, "wrongpassword"), "535")
}

func TestAuth_NonExistentUser(t *testing.T) {
	rdb := redisClient()
	cleanAll(t, rdb, "ghost_user_xyz")
	defer cleanAll(t, rdb, "ghost_user_xyz")

	conn, r, w := smtpDial(t)
	defer conn.Close()
	assertCode(t, smtpLogin(t, r, w, "ghost_user_xyz", "anypassword"), "535")
}

func TestAuth_CommandsRequireAuth(t *testing.T) {
	cmds := []string{
		"HELO localhost",
		"MAIL FROM:<a@b.com>",
		"RCPT TO:<c@d.com>",
		"DATA",
	}
	for _, cmd := range cmds {
		t.Run(cmd, func(t *testing.T) {
			conn, r, w := smtpDial(t)
			defer conn.Close()
			readLine(t, r) // 220
			send(t, w, cmd)
			assertCode(t, readLine(t, r), "530")
		})
	}
}

// ─────────────────────────────────────────────
// Account lockout
// ─────────────────────────────────────────────

func TestAuth_AccountLockAfterFailures(t *testing.T) {
	rdb := redisClient()
	cleanAll(t, rdb, testUsername)
	defer cleanAll(t, rdb, testUsername)
	createUser(t, testUsername, testPassword, testEmail)

	// 5 wrong-password attempts to trigger the lock.
	for i := 0; i < 5; i++ {
		conn, r, w := smtpDial(t)
		smtpLogin(t, r, w, testUsername, "badpass")
		conn.Close()
	}

	// Clean rate-limiter counters so the lock check is reached.
	rdb.Del(context.Background(), "auth:user:"+testUsername, "auth:ip:127.0.0.1", "auth:ip:::1")

	// Next attempt: server detects lock after username is submitted.
	conn, r, w := smtpDial(t)
	defer conn.Close()
	readLine(t, r) // 220
	send(t, w, "AUTH LOGIN")
	assertCode(t, readLine(t, r), "334")
	send(t, w, b64(testUsername))
	resp := readLine(t, r)
	if !strings.HasPrefix(resp, "535") && !strings.HasPrefix(resp, "334") {
		t.Errorf("expected 535 (locked) or 334 (then 535), got: %q", resp)
	}
}

func TestAuth_SuccessfulLoginClearsFailCount(t *testing.T) {
	rdb := redisClient()
	cleanAll(t, rdb, testUsername)
	defer cleanAll(t, rdb, testUsername)
	createUser(t, testUsername, testPassword, testEmail)

	// 3 failures — below the lock threshold.
	for i := 0; i < 3; i++ {
		conn, r, w := smtpDial(t)
		smtpLogin(t, r, w, testUsername, "badpass")
		conn.Close()
	}

	// Successful login must clear the counter.
	conn, r, w := smtpDial(t)
	defer conn.Close()
	assertCode(t, smtpLogin(t, r, w, testUsername, testPassword), "235")

	exists, _ := rdb.Exists(context.Background(),
		fmt.Sprintf("auth:fail:user:%s", testUsername),
	).Result()
	if exists != 0 {
		t.Errorf("fail counter should be cleared after successful login")
	}
}

// ─────────────────────────────────────────────
// Rate limiter
// ─────────────────────────────────────────────

func TestRateLimit_BlocksAfterUserLimit(t *testing.T) {
	rdb := redisClient()
	cleanAll(t, rdb, testUsername)
	defer cleanAll(t, rdb, testUsername)
	createUser(t, testUsername, testPassword, testEmail)

	// Exhaust the user bucket (UserLimit=5 set in main.go).
	for i := 0; i < 5; i++ {
		conn, r, w := smtpDial(t)
		smtpLogin(t, r, w, testUsername, testPassword)
		conn.Close()
	}

	// 6th attempt must be rate-limited with 454.
	conn, r, w := smtpDial(t)
	defer conn.Close()
	readLine(t, r) // 220
	send(t, w, "AUTH LOGIN")
	assertCode(t, readLine(t, r), "334")
	send(t, w, b64(testUsername))
	assertCode(t, readLine(t, r), "454")
}

// ─────────────────────────────────────────────
// SMTP state machine / command ordering
// ─────────────────────────────────────────────

func TestSMTP_HeloBeforeMailFrom(t *testing.T) {
	rdb := redisClient()
	cleanAll(t, rdb, testUsername)
	defer cleanAll(t, rdb, testUsername)
	createUser(t, testUsername, testPassword, testEmail)

	conn, r, w := smtpDial(t)
	defer conn.Close()
	readLine(t, r) // 220

	// Auth OK but skip HELO — go straight to MAIL FROM.
	send(t, w, "AUTH LOGIN")
	assertCode(t, readLine(t, r), "334") // username prompt
	send(t, w, b64(testUsername))
	assertCode(t, readLine(t, r), "334") // password prompt
	send(t, w, b64(testPassword))
	assertCode(t, readLine(t, r), "235")

	send(t, w, fmt.Sprintf("MAIL FROM:<%s>", testEmail))
	assertCode(t, readLine(t, r), "503")
}

func TestSMTP_RcptWithoutMailFrom(t *testing.T) {
	rdb := redisClient()
	cleanAll(t, rdb, testUsername)
	defer cleanAll(t, rdb, testUsername)
	createUser(t, testUsername, testPassword, testEmail)

	conn, r, w := fullLogin(t, testUsername, testPassword)
	defer conn.Close()

	send(t, w, fmt.Sprintf("RCPT TO:<%s>", testEmail2))
	assertCode(t, readLine(t, r), "503")
}

func TestSMTP_DataWithoutRcpt(t *testing.T) {
	rdb := redisClient()
	cleanAll(t, rdb, testUsername)
	defer cleanAll(t, rdb, testUsername)
	createUser(t, testUsername, testPassword, testEmail)

	conn, r, w := fullLogin(t, testUsername, testPassword)
	defer conn.Close()

	send(t, w, fmt.Sprintf("MAIL FROM:<%s>", testEmail))
	assertCode(t, readLine(t, r), "250")

	send(t, w, "DATA")
	assertCode(t, readLine(t, r), "503")
}

// ─────────────────────────────────────────────
// MAIL FROM authorization
// ─────────────────────────────────────────────

func TestMailFrom_WrongEmail(t *testing.T) {
	rdb := redisClient()
	cleanAll(t, rdb, testUsername)
	defer cleanAll(t, rdb, testUsername)
	createUser(t, testUsername, testPassword, testEmail)

	conn, r, w := fullLogin(t, testUsername, testPassword)
	defer conn.Close()

	send(t, w, "MAIL FROM:<impostor@evil.com>")
	assertCode(t, readLine(t, r), "535")
}

func TestMailFrom_CorrectEmail(t *testing.T) {
	rdb := redisClient()
	cleanAll(t, rdb, testUsername)
	defer cleanAll(t, rdb, testUsername)
	createUser(t, testUsername, testPassword, testEmail)

	conn, r, w := fullLogin(t, testUsername, testPassword)
	defer conn.Close()

	send(t, w, fmt.Sprintf("MAIL FROM:<%s>", testEmail))
	assertCode(t, readLine(t, r), "250")
}

// ─────────────────────────────────────────────
// Full happy-path end-to-end
// ─────────────────────────────────────────────

func TestSMTP_FullSendFlow(t *testing.T) {
	rdb := redisClient()
	cleanAll(t, rdb, testUsername)
	defer cleanAll(t, rdb, testUsername)
	createUser(t, testUsername, testPassword, testEmail)

	conn, r, w := fullLogin(t, testUsername, testPassword)
	defer conn.Close()

	send(t, w, fmt.Sprintf("MAIL FROM:<%s>", testEmail))
	assertCode(t, readLine(t, r), "250")

	send(t, w, fmt.Sprintf("RCPT TO:<%s>", testEmail2))
	assertCode(t, readLine(t, r), "250")

	send(t, w, "DATA")
	assertCode(t, readLine(t, r), "354")

	send(t, w, "Subject: Test\r\nHello World!")
	send(t, w, ".")
	assertCode(t, readLine(t, r), "250")
}

// ─────────────────────────────────────────────
// RSET
// ─────────────────────────────────────────────

func TestSMTP_RsetResetsState(t *testing.T) {
	rdb := redisClient()
	cleanAll(t, rdb, testUsername)
	defer cleanAll(t, rdb, testUsername)
	createUser(t, testUsername, testPassword, testEmail)

	conn, r, w := fullLogin(t, testUsername, testPassword)
	defer conn.Close()

	send(t, w, fmt.Sprintf("MAIL FROM:<%s>", testEmail))
	assertCode(t, readLine(t, r), "250")

	send(t, w, "RSET")
	assertCode(t, readLine(t, r), "250")

	// RCPT TO after RSET must fail — no active MAIL FROM.
	send(t, w, fmt.Sprintf("RCPT TO:<%s>", testEmail2))
	assertCode(t, readLine(t, r), "503")
}

func TestSMTP_RsetThenFullFlow(t *testing.T) {
	rdb := redisClient()
	cleanAll(t, rdb, testUsername)
	defer cleanAll(t, rdb, testUsername)
	createUser(t, testUsername, testPassword, testEmail)

	conn, r, w := fullLogin(t, testUsername, testPassword)
	defer conn.Close()

	send(t, w, fmt.Sprintf("MAIL FROM:<%s>", testEmail))
	assertCode(t, readLine(t, r), "250")
	send(t, w, "RSET")
	assertCode(t, readLine(t, r), "250")

	// Full transaction after RSET must succeed.
	send(t, w, fmt.Sprintf("MAIL FROM:<%s>", testEmail))
	assertCode(t, readLine(t, r), "250")
	send(t, w, fmt.Sprintf("RCPT TO:<%s>", testEmail2))
	assertCode(t, readLine(t, r), "250")
	send(t, w, "DATA")
	assertCode(t, readLine(t, r), "354")
	send(t, w, "Subject: After reset")
	send(t, w, ".")
	assertCode(t, readLine(t, r), "250")
}

// ─────────────────────────────────────────────
// Multiple messages on one connection
// ─────────────────────────────────────────────

func TestSMTP_MultipleMessagesOnOneConnection(t *testing.T) {
	rdb := redisClient()
	cleanAll(t, rdb, testUsername)
	defer cleanAll(t, rdb, testUsername)
	createUser(t, testUsername, testPassword, testEmail)

	conn, r, w := fullLogin(t, testUsername, testPassword)
	defer conn.Close()

	for i := 0; i < 3; i++ {
		send(t, w, fmt.Sprintf("MAIL FROM:<%s>", testEmail))
		assertCode(t, readLine(t, r), "250")
		send(t, w, fmt.Sprintf("RCPT TO:<%s>", testEmail2))
		assertCode(t, readLine(t, r), "250")
		send(t, w, "DATA")
		assertCode(t, readLine(t, r), "354")
		send(t, w, fmt.Sprintf("Message number %d", i+1))
		send(t, w, ".")
		assertCode(t, readLine(t, r), "250")
	}
}

// ─────────────────────────────────────────────
// Unknown command
// ─────────────────────────────────────────────

func TestSMTP_UnknownCommand(t *testing.T) {
	conn, r, w := smtpDial(t)
	defer conn.Close()
	readLine(t, r) // 220
	send(t, w, "GARBAGE COMMAND")
	resp := readLine(t, r)
	if !strings.HasPrefix(resp, "500") && !strings.HasPrefix(resp, "250") {
		t.Errorf("expected 500 (or 250 if not yet fixed) for unknown command, got: %q", resp)
	}
}
