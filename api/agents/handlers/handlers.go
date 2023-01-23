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

type RegistrationPayload struct {
	PublicIP  string `json:"public_ip"`
	SecretKey string `json:"secret_key"`
	PublicKey string `json:"public_key"`
	Name      string `json:"name"`
}
type UnverifiedRequest struct {
	PublicKey string `json:"public_key"`
	JwtToken  string `json:"jwt"`
}
type RegisterAgentResponse struct {
	Success   bool   `json:"success"`
	Error     string `json:"error"`
	PublicKey string `json:"public_key"`
	JwtToken  string `json:"jwt"`
}

func RegisterAgent(c *gin.Context) {
	var raw_request UnverifiedRequest
	var response RegisterAgentResponse
	err := c.BindJSON(&raw_request)
	if err != nil {
		response.Success = false
		response.Error = err.Error()
		c.JSON(400, response)
		return
	}
	// Verify JWT
	request_jwt_payload, err := sec.VerifyToken(raw_request.JwtToken, raw_request.PublicKey)
	if err != nil {
		response.Success = false
		response.Error = err.Error()
		c.JSON(401, response)
		return
	}
	// Unmarshal payload
	var request_payload RegistrationPayload
	err = json.Unmarshal([]byte(request_jwt_payload), &request_payload)
	if err != nil {
		response.Success = false
		response.Error = err.Error()
		c.JSON(500, response)
		return
	}
	if request_payload.SecretKey != SECRET_KEY {
		response.Success = false
		response.Error = "Invalid secret key"
		c.JSON(401, response)
		return
	}
	// Register agent
	agent := types.Agent{
		PublicIP:  request_payload.PublicIP,
		PublicKey: request_payload.PublicKey,
		Name:      request_payload.Name,
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
	response_jwt_payload, err := json.Marshal(agent)
	if err != nil {
		response.Success = false
		response.Error = err.Error()
		c.JSON(500, response)
		return
	}
	// Create JWT response_token
	response_token, err := sec.CreateToken(string(response_jwt_payload))
	if err != nil {
		response.Success = false
		response.Error = err.Error()
		c.JSON(500, response)
		return
	}
	response.JwtToken = response_token
	c.JSON(200, response)
}
