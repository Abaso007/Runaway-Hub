package clients

import (
	sec "github.com/RunawayVPN/Runaway-Hub/tools/security"
	"github.com/gin-gonic/gin"
)

// Middleware for JWT authentication
func JWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get JWT from header
		token := c.Request.Header.Get("Authorization")
		// Verify JWT
		payload, err := sec.VerifyToken(token, "")
		if err != nil {
			c.JSON(400, gin.H{
				"error": err.Error(),
			})
			c.Abort()
			return
		}
		// Add payload to context
		c.Set("payload", payload)
		// Continue
		c.Next()
	}
}
