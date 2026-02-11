package main

import (
	"bufio"
	"fmt"
	"net"
)

func SendSMTP(host string, from string, to string, body string) error {

	conn, err := net.Dial("tcp", host+":25")
	if err != nil {
		return err
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// read 220 greeting
	reader.ReadString('\n')

	fmt.Fprintf(conn, "HELO localhost\r\n")
	reader.ReadString('\n')

	fmt.Fprintf(conn, "MAIL FROM:<%s>\r\n", from)
	reader.ReadString('\n')

	fmt.Fprintf(conn, "RCPT TO:<%s>\r\n", to)
	reader.ReadString('\n')

	fmt.Fprintf(conn, "DATA\r\n")
	reader.ReadString('\n')

	fmt.Fprintf(conn, "%s\r\n.\r\n", body)
	reader.ReadString('\n')

	fmt.Fprintf(conn, "QUIT\r\n")

	return nil
}
