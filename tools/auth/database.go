package auth

// Uses an SQLite database to store agent information

import (
	"database/sql"
	"os"

	"github.com/RunawayVPN/Runaway-Hub/types"
	_ "github.com/mattn/go-sqlite3"
)

func init() {
	// Create database file if it doesn't exist
	// Check if database file exists
	if _, err := os.Stat("./auth.db"); os.IsNotExist(err) {
		// Create database file
		sqliteDB, err := sql.Open("sqlite3", "./auth.db")
		if err != nil {
			panic(err)
		}
		defer sqliteDB.Close()
		// Create table
		SqlStmt := `CREATE TABLE agents (public_ip TEXT PRIMARY KEY UNIQUE NOT NULL, public_key TEXT NOT NULL, identity TEXT NOT NULL, name TEXT NOT NULL, country TEXT, isp TEXT);`
		_, err = sqliteDB.Exec(SqlStmt)
		if err != nil {
			panic(err)
		}
	}
}

// RegisterAgent registers an agent with the database
func RegisterAgent(agent types.Agent) error {
	// Open database
	sqliteDB, err := sql.Open("sqlite3", "./auth.db")
	if err != nil {
		return err
	}
	defer sqliteDB.Close()
	// Check if agent already exists
	rows, err := sqliteDB.Query("SELECT * FROM agents WHERE public_ip = ?", agent.PublicIP)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		// Update agent with new information
		stmt, err := sqliteDB.Prepare("UPDATE agents SET public_key = ?, identity = ?, name = ? WHERE public_ip = ?, country = ?, isp = ?")
		if err != nil {
			return err
		}
		_, err = stmt.Exec(agent.PublicKey, agent.Identity, agent.Name, agent.PublicIP, agent.Country, agent.ISP)
		if err != nil {
			return err
		}
		return nil
	}
	// Insert agent into database
	stmt, err := sqliteDB.Prepare("INSERT INTO agents(public_ip, public_key, identity, name, country, isp) VALUES(?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	_, err = stmt.Exec(agent.PublicIP, agent.PublicKey, agent.Identity, agent.Name)
	if err != nil {
		return err
	}
	return nil
}

// GetAgent gets an agent from the database
func GetAgent(publicIP string) (types.Agent, error) {
	// Open database
	sqliteDB, err := sql.Open("sqlite3", "./auth.db")
	if err != nil {
		return types.Agent{}, err
	}
	defer sqliteDB.Close()
	// Get agent from database
	rows, err := sqliteDB.Query("SELECT * FROM agents WHERE public_ip = ?", publicIP)
	if err != nil {
		return types.Agent{}, err
	}
	defer rows.Close()
	// Get agent from rows
	var agent types.Agent
	for rows.Next() {
		err = rows.Scan(&agent.PublicIP, &agent.PublicKey, &agent.Identity, &agent.Name)
		if err != nil {
			return types.Agent{}, err
		}
	}
	return agent, nil
}

// GetAgents gets all agents from the database
func GetAgents() ([]types.Agent, error) {
	// Open database
	sqliteDB, err := sql.Open("sqlite3", "./auth.db")
	if err != nil {
		return nil, err
	}
	defer sqliteDB.Close()
	// Get agents from database
	rows, err := sqliteDB.Query("SELECT * FROM agents")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	// Get agents from rows
	var agents []types.Agent
	for rows.Next() {
		var agent types.Agent
		err = rows.Scan(&agent.PublicIP, &agent.PublicKey, &agent.Identity, &agent.Name)
		if err != nil {
			return nil, err
		}
		agents = append(agents, agent)
	}
	return agents, nil
}
