package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	//"os"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var (
	db    *sql.DB
	store = sessions.NewCookieStore([]byte("your-secret-key")) // Change this secret key
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
	http.ListenAndServe(":8080", r)
}

// Utility functions

func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	t, err := template.ParseFiles("templates/" + tmpl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	t.Execute(w, data)
}

func isLoggedIn(r *http.Request) bool {
	session, _ := store.Get(r, "session-name")
	return session.Values["username"] != nil
}

func getSessionUser(r *http.Request) (User, error) {
	session, _ := store.Get(r, "session-name")
	username, ok := session.Values["username"].(string)
	if !ok {
		return User{}, fmt.Errorf("no user in session")
	}

	user, err := getUserByUsername(username)
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

	renderTemplate(w, "home.html", posts)
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

		session, _ := store.Get(r, "session-name")
		session.Values["username"] = user.Username
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	session.Options.MaxAge = -1
	session.Save(r, w)

	http.Redirect(w, r, "/login", http.StatusFound)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "register.html", nil)
}

func registerPostHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")

	_, err := getUserByUsername(username)
	if err == nil {
		http.Error(w, "Username already exists", http.StatusBadRequest)
		return
	} else if err != sql.ErrNoRows {
		http.Error(w, "Database error", http.StatusInternalServerError)
		log.Println("Error checking username:", err)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		log.Println("Error hashing password:", err)
		return
	}

	err = createUser(username, email, hashedPassword)
	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		log.Println("Error creating user:", err)
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

	return posts, nil
}

func getPostByID(postID string) (Post, error) {
	var post Post
	query := "SELECT id, user_id, header, content, tags, image, created_at FROM posts WHERE id=$1"
	err := db.QueryRow(query, postID).Scan(&post.ID, &post.UserID, &post.Header, &post.Content, &post.Tags, &post.Image, &post.CreatedAt)
	return post, err
}
