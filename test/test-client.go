package main

import (
	"bufio"
	"fmt"
	"net"
)

func main() {
	conn, err := net.Dial("tcp", "localhost:8000")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	line, _ := reader.ReadString('\n')
	fmt.Print("Server:", line)

	// send commands before DATA
	preData := []string{
		"HELO test\r\n",
		"RCPT TO:<bob@test.com>\r\n",
		"MAIL FROM:<alice@test.com>\r\n",
		"RCPT TO:<bob@test.com>\r\n",
		"DATA\r\n",
	}

	for _, cmd := range preData {
		conn.Write([]byte(cmd))
		resp, _ := reader.ReadString('\n')
		fmt.Print("Server:", resp)
	}

	conn.Write([]byte("Hello Bob\r\n"))
	conn.Write([]byte("This is a test mail\r\n"))
	conn.Write([]byte(".\r\n"))

	resp, _ := reader.ReadString('\n')
	fmt.Print("Server:", resp)

	conn.Write([]byte("QUIT\r\n"))
	resp, _ = reader.ReadString('\n')
	fmt.Print("Server:", resp)

}
