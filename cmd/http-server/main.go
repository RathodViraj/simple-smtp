package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

var ctx = context.Background()

var rdb = redis.NewClient(&redis.Options{
	Addr: "localhost:6379",
})

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

func createUserHandler(w http.ResponseWriter, r *http.Request) {
	var u User
	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(u.Password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		http.Error(w, "hash error", 500)
		return
	}

	err = rdb.HSet(ctx, "user:"+u.Username, map[string]interface{}{
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
