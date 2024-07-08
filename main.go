package main

import (
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var (
	db     *sql.DB
	jwtKey = []byte("your-secret-key")
)

type User struct {
	ID       int
	Username string
	Email    string
	Password []byte // hashed password
}

type Post struct {
	ID        int
	UserID    int
	Header    string
	Content   string
	Tags      string
	Image     string
	CreatedAt string
}

type ErrorMsg struct {
	Msg string
}

type HomeData struct {
	Posts    []Post
	LoggedIn bool
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func main() {
	// Connect to PostgreSQL database
	var err error
	db, err = sql.Open("postgres", "postgres://jonnalagaddavenkatasathyakrishna:1@localhost/blogdb?sslmode=disable")
	if err != nil {
		log.Fatal("Error connecting to the database:", err)
	}
	defer db.Close()

	// Verify database connection
	err = db.Ping()
	if err != nil {
		log.Fatal("Error pinging database:", err)
	}

	// Initialize HTTP server and routes
	setupRoutes()
}

func setupRoutes() {
	r := mux.NewRouter()

	// Serve static files
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))

	// Define routes
	r.HandleFunc("/", homeHandler).Methods("GET")
	r.HandleFunc("/post/{id}", viewPostHandler).Methods("GET")
	r.HandleFunc("/login", loginHandler).Methods("GET", "POST")
	r.HandleFunc("/logout", logoutHandler).Methods("POST")
	r.HandleFunc("/register", registerHandler).Methods("GET")
	r.HandleFunc("/register", registerPostHandler).Methods("POST")
	r.HandleFunc("/posts/new", newPostHandler).Methods("GET")
	r.HandleFunc("/posts/create", createPostHandler).Methods("POST")

	// Start server
	log.Println("Starting server on :8080")
	err := http.ListenAndServe(":8080", r)
	if err != nil {
		fmt.Println("Unable to start the server!!", err.Error())
		return
	}
}

// Utility functions

func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	t, err := template.ParseFiles("templates/" + tmpl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = t.Execute(w, data)
	if err != nil {
		fmt.Println("Unable to load the template: ", err.Error())
		return
	}
}

func isLoggedIn(r *http.Request) bool {
	tokenCookie, err := r.Cookie("token")
	if err != nil {
		return false
	}

	tokenStr := tokenCookie.Value
	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	return err == nil && tkn.Valid
}

func getSessionUser(r *http.Request) (User, error) {
	tokenCookie, err := r.Cookie("token")
	if err != nil {
		return User{}, fmt.Errorf("no token in cookie")
	}

	tokenStr := tokenCookie.Value
	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !tkn.Valid {
		return User{}, fmt.Errorf("invalid token")
	}

	user, err := getUserByUsername(claims.Username)
	if err != nil {
		return User{}, err
	}

	return user, nil
}

// Handlers

func homeHandler(w http.ResponseWriter, r *http.Request) {
	posts, err := getAllPosts()
	if err != nil {
		http.Error(w, "Unable to load posts", http.StatusInternalServerError)
		return
	}

	loggedIn := isLoggedIn(r)

	data := HomeData{
		Posts:    posts,
		LoggedIn: loggedIn,
	}

	renderTemplate(w, "home.html", data)
}

func viewPostHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	postID := vars["id"]

	post, err := getPostByID(postID)
	if err != nil {
		http.Error(w, "Unable to load post", http.StatusInternalServerError)
		return
	}

	renderTemplate(w, "post.html", post)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		renderTemplate(w, "login.html", nil)
	case "POST":
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, err := verifyUser(username, password)
		if err != nil {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		expirationTime := time.Now().Add(24 * time.Hour)
		claims := &Claims{
			Username: user.Username,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			http.Error(w, "Unable to generate token", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:    "token",
			Value:   tokenString,
			Expires: expirationTime,
		})

		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   "token",
		Value:  "",
		MaxAge: -1,
	})

	http.Redirect(w, r, "/login", http.StatusFound)
}

func registerHandler(w http.ResponseWriter, _ *http.Request) {
	renderTemplate(w, "register.html", nil)
}

func registerPostHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	msg := ErrorMsg{Msg: ""}
	_, err := getUserByUsername(username)
	if err == nil {
		//http.Error(w, "Username already exists", http.StatusBadRequest)
		//http.Redirect(w, r, "/register", http.StatusBadRequest)
		msg.Msg = "Username already exists"
		renderTemplate(w, "register.html", msg)
		return
	} else if !errors.Is(err, sql.ErrNoRows) {
		msg.Msg = "Unable to register the user"
		log.Println("Error checking username:", err)
		renderTemplate(w, "register.html", msg)
		//http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		msg.Msg = "Unable to register the user"
		log.Println("Error hashing password:", err)
		renderTemplate(w, "register.html", msg)
		//w.WriteHeader(http.StatusBadRequest)
		//w.Header()
		//http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	err = createUser(username, email, hashedPassword)
	if err != nil {
		//http.Error(w, "Failed to create user", http.StatusInternalServerError)
		log.Println("Error creating user:", err)
		msg.Msg = "Unable to register the user"
		renderTemplate(w, "register.html", msg)
		return
	}

	http.Redirect(w, r, "/login", http.StatusFound)
}

func newPostHandler(w http.ResponseWriter, r *http.Request) {
	if !isLoggedIn(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	renderTemplate(w, "new_post.html", nil)
}

func createPostHandler(w http.ResponseWriter, r *http.Request) {
	if !isLoggedIn(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	user, err := getSessionUser(r)
	if err != nil {
		http.Error(w, "Unable to get session user", http.StatusInternalServerError)
		return
	}

	header := r.FormValue("header")
	content := r.FormValue("content")
	tags := r.FormValue("tags")
	image := r.FormValue("image") // Handle image upload separately

	err = createPost(user.ID, header, content, tags, image)
	if err != nil {
		http.Error(w, "Unable to create post", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

// Database functions

func getUserByUsername(username string) (User, error) {
	var user User
	query := "SELECT id, username, email, password FROM users WHERE username=$1"
	err := db.QueryRow(query, username).Scan(&user.ID, &user.Username, &user.Email, &user.Password)
	return user, err
}

func createUser(username, email string, password []byte) error {
	_, err := db.Exec("INSERT INTO users (username, email, password) VALUES ($1, $2, $3)", username, email, password)
	return err
}

func verifyUser(username, password string) (User, error) {
	user, err := getUserByUsername(username)
	if err != nil {
		return user, err
	}

	err = bcrypt.CompareHashAndPassword(user.Password, []byte(password))
	if err != nil {
		return user, fmt.Errorf("invalid password")
	}

	return user, nil
}

func createPost(userID int, header, content, tags, image string) error {
	_, err := db.Exec("INSERT INTO posts (user_id, header, content, tags, image) VALUES ($1, $2, $3, $4, $5)", userID, header, content, tags, image)
	return err
}

func getAllPosts() ([]Post, error) {
	rows, err := db.Query("SELECT id, user_id, header, content, tags, image, created_at FROM posts ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var post Post
		err := rows.Scan(&post.ID, &post.UserID, &post.Header, &post.Content, &post.Tags, &post.Image, &post.CreatedAt)
		if err != nil {
			return nil, err
		}
		posts = append(posts, post)
	}
	//fmt.Println(posts)

	return posts, nil
}

func getPostByID(postID string) (Post, error) {
	var post Post
	query := "SELECT id, user_id, header, content, tags, image, created_at FROM posts WHERE id=$1"
	err := db.QueryRow(query, postID).Scan(&post.ID, &post.UserID, &post.Header, &post.Content, &post.Tags, &post.Image, &post.CreatedAt)
	return post, err
}
