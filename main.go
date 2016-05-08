package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

// using asymmetric crypto/RSA keys
// location of the files used for signing and verfication
const (
	privKeyPath = "keys/app.rsa"
	pubKeyPath  = "keys/app.rsa.pub"
)

var (
	verifyKey, signKey []byte
)

// struct User for parsing login credentials
type User struct {
	UserName string `json:"username"`
	Password string `json:"password"`
}

// read the key files before starting the http handlers
func init() {
	var err error
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal("Error getting the working directory path.")
		return
	}
	cwd += "/jwt-token"
	signKey, err = ioutil.ReadFile(filepath.Join(cwd, privKeyPath))
	if err != nil {
		log.Fatalf("Error reading private key:", err)
		return
	}

	verifyKey, err = ioutil.ReadFile(filepath.Join(cwd, pubKeyPath))
	if err != nil {
		log.Fatal("Error reading private key")
		return
	}
}

// reads the login credentials, checks them and creates the JWT token
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		// something went wrong while decoding the response body.
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error decoding response body:", err)
	}

	if user.UserName != "german" && user.Password != "pass123" {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "Incorrect login credentials")
	}

	// create a jwt signer
	j := jwt.New(jwt.GetSigningMethod("RS256"))
	j.Claims["UserInfo"] = user
	j.Claims["exp"] = time.Now().Add(time.Minute * 20).Unix()
	tokenStr, err := j.SignedString(signKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error:", err)
	}
	response := Token{tokenStr}
	jsonResponse(response, w)
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := jwt.ParseFromRequest(r, func(token *jwt.Token) (interface{}, error) {
			return verifyKey, nil
		})

		log.Printf("Error:", err)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "Error parsing request:", err)
			return
		}

		if token.Valid {
			next.ServeHTTP(w, r)
		} else {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "Invalid token!")
			return
		}
	})
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	response := Response{"Authentication success!"}
	jsonResponse(response, w)
}

type Response struct {
	Text string `json:"text"`
}

type Token struct {
	Token string `json:"token"`
}

func jsonResponse(response interface{}, w http.ResponseWriter) {
	json, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(json)
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/login", loginHandler).Methods("POST")
	ah := http.HandlerFunc(authHandler)
	r.Handle("/auth", authMiddleware(ah)).Methods("POST")

	server := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}
	log.Println("Listening on port 8080.")
	server.ListenAndServe()
}
