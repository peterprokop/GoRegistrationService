package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

var Db *sql.DB //created outside to make it global.
var jwtSecretKey = []byte("secret-key")

func ConnectDatabase() {
	host := "localhost"
	port := 5432
	user := "postgres"
	dbname := "goddit"
	pass := "postgres"

	psqlSetup := fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s sslmode=disable",
		host, port, user, dbname, pass)
	db, errSql := sql.Open("postgres", psqlSetup)
	if errSql != nil {
		log.Println("There is an error while connecting to the database ", errSql)
		panic(errSql)
	} else {
		Db = db
		log.Println("Successfully connected to database!")
	}
}

func createJWTToken(username string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"username": username,
			"exp":      time.Now().Add(time.Hour * 24 * 7).Unix(),
		})

	tokenString, err := token.SignedString(jwtSecretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func verifyJWTToken(tokenString string) error {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecretKey, nil
	})

	if err != nil {
		return err
	}

	if !token.Valid {
		return fmt.Errorf("invalid token")
	}

	return nil
}

type User struct {
	id       uuid.UUID
	email    sql.NullString
	name     sql.NullString
	password string
}

// For POST /user/register/ endpoint
type UserRegisterJSON struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// For POST /user/login/ endpoint
type UserLoginJSON struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {
	router := gin.Default()
	ConnectDatabase()

	router.POST("/user/register/", func(ctx *gin.Context) {
		byteValue, err := io.ReadAll(ctx.Request.Body)
		if err != nil {
			log.Println(err)
			ctx.AbortWithStatusJSON(400, "Couldn't create the new user.")
			return
		}

		var user UserRegisterJSON

		err = json.Unmarshal(byteValue, &user)
		if err != nil {
			log.Println(err)
			ctx.AbortWithStatusJSON(400, "Couldn't create the new user.")
			return
		}

		// TODO: verify username
		// TODO: verify email
		// TODO: verify password

		// 12 should be reasonable cost for now
		hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 12)
		if err != nil {
			log.Println(err)
			ctx.AbortWithStatusJSON(400, "Couldn't create the new user.")
			return
		}

		id, _ := uuid.NewV7()
		_, err = Db.Exec(
			"insert into users(id, email, name, password) values ($1, $2, $3, $4)",
			id, user.Email, user.Username, hash,
		)

		if err != nil {
			log.Println(err)
			ctx.AbortWithStatusJSON(400, "Couldn't create the new user.")
		} else {
			ctx.JSON(http.StatusOK, "User is successfully created.")
		}
	})

	router.POST("/user/login/", func(ctx *gin.Context) {
		errorMessage := "Can't login"
		byteValue, err := io.ReadAll(ctx.Request.Body)
		if err != nil {
			log.Println(err)
			ctx.AbortWithStatusJSON(400, errorMessage)
			return
		}

		var user UserLoginJSON

		err = json.Unmarshal(byteValue, &user)
		if err != nil {
			log.Println(err)
			ctx.AbortWithStatusJSON(400, errorMessage)
			return
		}

		var password string
		err = Db.QueryRow("SELECT password FROM users WHERE name = $1", user.Username).Scan(&password)
		if err != nil {
			log.Println(err)
			ctx.AbortWithStatusJSON(400, errorMessage)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(password), []byte(user.Password))

		token, err := createJWTToken(user.Username)

		if err != nil {
			log.Println(err)
			ctx.AbortWithStatusJSON(400, errorMessage)
			return
		} else {
			ctx.JSON(http.StatusOK, gin.H{
				"token": token,
			})
		}
	})

	// Protected endpoint
	router.GET("/user/get_all/", func(ctx *gin.Context) {
		tokenString := ctx.GetHeader("Authorization")

		if tokenString == "" {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		tokenString = tokenString[len("Bearer "):]

		err := verifyJWTToken(tokenString)
		if err != nil {
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		rows, err := Db.Query("SELECT * FROM users")
		if err != nil {
			ctx.String(http.StatusInternalServerError, "Db error")
		}
		defer rows.Close()

		users := []map[string]any{}

		for rows.Next() {
			var user User
			if err := rows.Scan(&user.id, &user.email, &user.name, &user.password); err != nil {
				// Error handling
				log.Println(err)
				panic(err)
			}
			users = append(users, gin.H{
				"name":  user.name.String,
				"email": user.email.String,
			})
		}

		ctx.JSON(http.StatusOK, users)
	})

	router.Run(":8080")
}
