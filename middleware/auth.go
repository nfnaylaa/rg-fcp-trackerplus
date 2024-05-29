package middleware

import (
	"a21hc3NpZ25tZW50/model"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

func Auth() gin.HandlerFunc {
	return gin.HandlerFunc(func(ctx *gin.Context) {
		cookie, err := ctx.Cookie("session_token")
		if err != nil {
			if ctx.GetHeader("Content-Type") == "application/json" {
				ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			} else {
				ctx.Redirect(303, "/login")
			}
			ctx.Abort()
			return
		}
		claims := &model.Claims{}
		token, err := jwt.ParseWithClaims(cookie, claims, func(t *jwt.Token) (interface{}, error) {
			return []byte(model.JwtKey), nil
		})
		if err != nil || !token.Valid {
			ctx.JSON(400, gin.H{"error": "Unathorized"})
			ctx.Abort()
			return
		}

		ctx.Set("email", claims.Email)

		ctx.Next()
	})
}
