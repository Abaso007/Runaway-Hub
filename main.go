// Gin server for a VPN service
package main

import (
	agent_handlers "github.com/RunawayVPN/Runaway-Hub/api/agents/handlers"
	sec "github.com/RunawayVPN/Runaway-Hub/tools/security"
	"github.com/gin-gonic/gin"
)

func main() {
	go jwt_test()
	go agent_test()
	select {}
}

func agent_test() {
	agent_testing_server := gin.Default()
	agent_testing_server.POST("/agent/registration", agent_handlers.RegisterAgent)
	agent_testing_server.Run(":8080")
}

func jwt_test() {
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
	jwt_testing_server.POST("/testing/verify_jwt", func(c *gin.Context) {
		// JSON body
		type JSONBody struct {
			JWT string `json:"jwt"`
		}
		var jsonBody JSONBody
		err := c.BindJSON(&jsonBody)
		if err != nil {
			c.JSON(400, gin.H{
				"error": err.Error(),
			})
			return
		}
		// Verify JWT
		payload, err := sec.VerifyToken(jsonBody.JWT)
		if err != nil {
			c.JSON(400, gin.H{
				"error": err.Error(),
			})
			return
		}
		c.JSON(200, gin.H{
			"payload": payload,
		})
	})
	jwt_testing_server.Run(":8081")
}
