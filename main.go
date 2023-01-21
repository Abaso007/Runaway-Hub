// Gin server for a VPN service
package main

import (
	sec "github.com/RunawayVPN/Runaway-Hub/tools/security"
	"github.com/gin-gonic/gin"
)

func main() {
	jwt_testing_server := gin.Default()
	jwt_testing_server.GET("/testing/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	jwt_testing_server.GET("/testing/get_jwt", func(c *gin.Context) {
		jwt, err := sec.CreateToken(`{"field": "value"}`)
		if err != nil {
			c.JSON(500, gin.H{
				"error": err.Error(),
			})
			return
		}
		c.JSON(200, gin.H{
			"jwt": jwt,
		})
	})
	jwt_testing_server.Run() // listen and serve on
}
