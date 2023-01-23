package server

// The agents need to be authorized. This should be done with a JWT token handed out by the server
// when the agent is registered. The token should be stored in the agent's config file and sent

import (
	_ "encoding/json"

	"github.com/gin-gonic/gin"
)

const SECRET_KEY = "secret"

func RegisterAgent(c *gin.Context) {
	type RegisterAgentRequest struct {
		PublicIP  string `json:"public_ip"`
		SecretKey string `json:"secret_key"`
		PublicKey string `json:"public_key"`
	}
	type RegisterAgentResponse struct {
		Success   bool   `json:"success"`
		Error     string `json:"error"`
		PublicKey string `json:"public_key"`
		Identity  string `json:"identity"`
	}
	var request RegisterAgentRequest
	var response RegisterAgentResponse
	err := c.BindJSON(&request)
	if err != nil {
		response.Success = false
		response.Error = err.Error()
		c.JSON(400, response)
		return
	}
	if request.SecretKey != SECRET_KEY {
		response.Success = false
		response.Error = "Invalid secret key"
		c.JSON(401, response)
		return
	}
}
