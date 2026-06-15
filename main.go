package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/mail"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var Db *sql.DB
var jwtSecretKey []byte

func ConnectDatabase() {
	psqlSetup := fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s sslmode=disable",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_PASSWORD"),
	)

	// host, port, user, dbname, pass)
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

func verifyEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

type User struct {
	id       uuid.UUID
	email    sql.NullString
	name     sql.NullString
	password string
}

const minPasswordLength int = 7
const maxPasswordLength int = 32

const minUsernameLength int = 2
const maxUsernameLength int = 32

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
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	jwtSecretKeyString := os.Getenv("JWT_SECRET_KEY")
	if jwtSecretKeyString == "" {
		panic(errors.New("No JWT secret in environment"))
	}

	jwtSecretKey = []byte(jwtSecretKeyString)

	router := gin.Default()
	ConnectDatabase()

	router.POST("/user/register/", func(ctx *gin.Context) {
		byteValue, err := io.ReadAll(ctx.Request.Body)
		if err != nil {
			log.Println(err)
			ctx.AbortWithStatusJSON(http.StatusBadRequest, "Couldn't create the new user.")
			return
		}

		var user UserRegisterJSON

		err = json.Unmarshal(byteValue, &user)
		if err != nil {
			log.Println(err)
			ctx.AbortWithStatusJSON(http.StatusBadRequest, "Couldn't create the new user.")
			return
		}

		if len(user.Username) > maxUsernameLength || len(user.Username) < minUsernameLength {
			log.Println("Invalid user name: " + user.Username)
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"message": "Invalid user name",
			})
			return
		}

		if !verifyEmail(user.Email) {
			log.Println("Invalid email: " + user.Email)
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"message": "Invalid email",
			})
			return
		}

		if len(user.Password) > maxPasswordLength || len(user.Password) < minPasswordLength {
			log.Println("Invalid password: " + user.Password)
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"message": "Invalid password",
			})
			return
		}

		// 12 should be reasonable cost for now
		hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 12)
		if err != nil {
			log.Println(err)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, "Couldn't create the new user.")
			return
		}

		id, _ := uuid.NewV7()
		_, err = Db.Exec(
			"insert into users(id, email, name, password) values ($1, $2, $3, $4)",
			id, user.Email, user.Username, hash,
		)

		if err != nil {
			log.Println(err)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, "Couldn't create the new user.")
		} else {
			ctx.JSON(http.StatusOK, gin.H{
				"message": "User is successfully created",
			})
		}
	})

	router.POST("/user/login/", func(ctx *gin.Context) {
		errorMessage := "Can't login"
		byteValue, err := io.ReadAll(ctx.Request.Body)
		if err != nil {
			log.Println(err)
			ctx.AbortWithStatusJSON(http.StatusBadRequest, errorMessage)
			return
		}

		var user UserLoginJSON

		err = json.Unmarshal(byteValue, &user)
		if err != nil {
			log.Println(err)
			ctx.AbortWithStatusJSON(http.StatusBadRequest, errorMessage)
			return
		}

		var password string
		err = Db.QueryRow("SELECT password FROM users WHERE name = $1", user.Username).Scan(&password)
		if err != nil {
			log.Println(err)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, errorMessage)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(password), []byte(user.Password))

		token, err := createJWTToken(user.Username)

		if err != nil {
			log.Println(err)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, errorMessage)
			return
		} else {
			ctx.JSON(http.StatusOK, gin.H{
				"token": token,
			})
		}
	})

	// Protected endpoints
	adminRoutes := router.Group("/admin")
	adminRoutes.Use(func(ctx *gin.Context) {
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
	})
	{
		adminRoutes.GET("/users/page/:page", func(ctx *gin.Context) {
			pageSize := 50
			page, err := strconv.Atoi(ctx.Param("page"))
			if err != nil || page < 1 {
				ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
					"message": "Wrong page provided",
				})
				return
			}

			offset := (page - 1) * pageSize
			rows, err := Db.Query("SELECT * FROM users ORDER BY id LIMIT $1 OFFSET $2", pageSize, offset)
			if err != nil {
				ctx.String(http.StatusInternalServerError, "Db error")
				return
			}
			defer rows.Close()

			users := []map[string]any{}

			for rows.Next() {
				var user User
				if err := rows.Scan(&user.id, &user.email, &user.name, &user.password); err != nil {
					log.Println(err)
					panic(err)
				}
				users = append(users, gin.H{
					"id":    user.id,
					"name":  user.name.String,
					"email": user.email.String,
				})
			}

			ctx.JSON(http.StatusOK, users)
		})
	}

	router.Run(":8080")
}
