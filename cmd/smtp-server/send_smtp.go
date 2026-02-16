package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	smtpDialTimeout  = 30 * time.Second
	smtpReadTimeout  = 60 * time.Second
	smtpWriteTimeout = 30 * time.Second
)

func SendSMTP(host string, from string, to string, body string) error {
	conn, err := net.DialTimeout("tcp", host, smtpDialTimeout)
	if err != nil {
		return fmt.Errorf("dial %s: %w", host, err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Helper: read a response line and verify the expected code.
	expect := func(wantCode string) error {
		conn.SetReadDeadline(time.Now().Add(smtpReadTimeout))
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read response: %w", err)
		}
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, wantCode) {
			return fmt.Errorf("expected %s, got %q", wantCode, line)
		}
		return nil
	}

	// Helper: write a command with a deadline.
	sendCmd := func(format string, args ...any) error {
		conn.SetWriteDeadline(time.Now().Add(smtpWriteTimeout))
		_, err := fmt.Fprintf(conn, format, args...)
		return err
	}

	// 220 greeting
	if err := expect("220"); err != nil {
		return fmt.Errorf("greeting: %w", err)
	}

	if err := sendCmd("HELO localhost\r\n"); err != nil {
		return err
	}
	if err := expect("250"); err != nil {
		return fmt.Errorf("HELO: %w", err)
	}

	if err := sendCmd("MAIL FROM:<%s>\r\n", from); err != nil {
		return err
	}
	if err := expect("250"); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}

	if err := sendCmd("RCPT TO:<%s>\r\n", to); err != nil {
		return err
	}
	if err := expect("250"); err != nil {
		return fmt.Errorf("RCPT TO: %w", err)
	}

	if err := sendCmd("DATA\r\n"); err != nil {
		return err
	}
	if err := expect("354"); err != nil {
		return fmt.Errorf("DATA: %w", err)
	}

	if err := sendCmd("%s\r\n.\r\n", body); err != nil {
		return err
	}
	if err := expect("250"); err != nil {
		return fmt.Errorf("end-of-data: %w", err)
	}

	_ = sendCmd("QUIT\r\n")
	// Best-effort read of 221; don't fail if the server closes early.
	_ = expect("221")

	return nil
}
