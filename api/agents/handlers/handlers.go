package handlers

// The agents need to be authorized. This should be done with a JWT token handed out by the server
// when the agent is registered. The token should be stored in the agent's config file and sent

import (
	"encoding/json"

	"github.com/RunawayVPN/Runaway-Hub/tools/auth"
	sec "github.com/RunawayVPN/Runaway-Hub/tools/security"
	"github.com/RunawayVPN/Runaway-Hub/types"
	"github.com/gin-gonic/gin"
)

const SECRET_KEY = "secret"

func RegisterAgent(c *gin.Context) {
	type RegisterAgentRequest struct {
		PublicIP  string `json:"public_ip"`
		SecretKey string `json:"secret_key"`
		PublicKey string `json:"public_key"`
		Name      string `json:"name"`
	}
	type RegisterAgentResponse struct {
		Success   bool   `json:"success"`
		Error     string `json:"error"`
		PublicKey string `json:"public_key"`
		JwtToken  string `json:"jwt"`
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
	// Register agent
	agent := types.Agent{
		PublicIP:  request.PublicIP,
		PublicKey: request.PublicKey,
		Name:      request.Name,
		Identity:  "agent",
	}
	err = auth.RegisterAgent(agent)
	if err != nil {
		response.Success = false
		response.Error = err.Error()
		c.JSON(500, response)
		return
	}
	// Construct response
	response.Success = true
	response.PublicKey = sec.EncodeBS(sec.Public_key)
	// Construct JWT payload with agent
	payload, err := json.Marshal(agent)
	if err != nil {
		response.Success = false
		response.Error = err.Error()
		c.JSON(500, response)
		return
	}
	// Create JWT token
	token, err := sec.CreateToken(string(payload))
	if err != nil {
		response.Success = false
		response.Error = err.Error()
		c.JSON(500, response)
		return
	}
	response.JwtToken = token
	c.JSON(200, response)
}
