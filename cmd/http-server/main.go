package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

var rdb = redis.NewClient(&redis.Options{
	Addr: "localhost:6379",
})

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

func createUserHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancle := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancle()

	var u User
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if u.Username == "" || u.Password == "" || u.Email == "" {
		http.Error(w, "username, password and email are required", http.StatusBadRequest)
		return
	}
	key := "user:" + u.Username
	exists, err := rdb.Exists(ctx, key).Result()
	if err != nil {
		log.Println(err)
		http.Error(w, "server failed", http.StatusInternalServerError)
		return
	}
	if exists == 1 {
		http.Error(w, "username exits", http.StatusBadRequest)
		return
	}

	if exists == 1 {
		fmt.Println("Key exists")
	} else {
		fmt.Println("Key does not exist")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(u.Password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		http.Error(w, "hash error", 500)
		return
	}

	err = rdb.HSet(ctx, key, map[string]interface{}{
		"password": string(hashedPassword),
		"email":    u.Email,
	}).Err()

	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("User created"))
}

func main() {
	http.HandleFunc("/create-user", createUserHandler)
	log.Println("User service running on :9000")
	http.ListenAndServe(":9000", nil)
}
