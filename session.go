package main

// Web sessions, each owning one IRC connection to soju.
//
// The password is kept in memory for the lifetime of the session and never
// written anywhere: it is needed to redial when soju restarts, which otherwise
// would log everybody out. Nothing is persisted, so restarting this program ends
// every session.

import (
	"errors"
	"net/http"
	"sync"
	"time"
)

const cookieName = "soju_webadmin"

type Session struct {
	ID   string
	CSRF string

	mu       sync.Mutex
	user     string
	password string
	cl       *Client
	lastUsed time.Time
	flash    *Flash
}

// Flash carries one message across the redirect that follows a POST.
type Flash struct {
	Text string
	Bad  bool
}

func (s *Session) SetFlash(text string, bad bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flash = &Flash{Text: text, Bad: bad}
}

func (s *Session) TakeFlash() *Flash {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.flash
	s.flash = nil
	return f
}

func (s *Session) User() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.user
}

// Credentials are needed to open the extra connections a manual watcher check
// binds to each network. They never leave the process.
func (s *Session) Credentials() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.user, s.password
}

func (s *Session) IsAdmin() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cl != nil && s.cl.IsAdmin
}

// Do runs an operation on the session's connection. If the connection turns out
// to be gone — soju restarted, the container was updated — it redials once and
// retries, so the page the user asked for still renders.
func (s *Session) Do(cfg ServerConfig, fn func(*Client) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastUsed = time.Now()

	if s.cl == nil {
		if err := s.redial(cfg); err != nil {
			return err
		}
	}
	err := fn(s.cl)
	if errors.Is(err, errClosed) {
		if rerr := s.redial(cfg); rerr != nil {
			return rerr
		}
		err = fn(s.cl)
	}
	return err
}

// redial replaces the connection. The caller holds the lock.
func (s *Session) redial(cfg ServerConfig) error {
	if s.cl != nil {
		s.cl.Close()
		s.cl = nil
	}
	cl, err := Dial(cfg, s.user, s.password)
	if err != nil {
		return err
	}
	s.cl = cl
	return nil
}

func (s *Session) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cl != nil {
		s.cl.Close()
		s.cl = nil
	}
}

type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*Session
	idle     time.Duration
}

func NewSessionStore(idle time.Duration) *SessionStore {
	st := &SessionStore{sessions: map[string]*Session{}, idle: idle}
	go st.reap()
	return st
}

// New authenticates against soju and, on success, opens a session.
func (st *SessionStore) New(cfg ServerConfig, user, password string) (*Session, error) {
	cl, err := Dial(cfg, user, password)
	if err != nil {
		return nil, err
	}
	s := &Session{
		ID:       randToken(24),
		CSRF:     randToken(16),
		user:     user,
		password: password,
		cl:       cl,
		lastUsed: time.Now(),
	}
	st.mu.Lock()
	st.sessions[s.ID] = s
	st.mu.Unlock()
	return s, nil
}

func (st *SessionStore) Get(r *http.Request) *Session {
	ck, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.sessions[ck.Value]
}

func (st *SessionStore) Delete(id string) {
	st.mu.Lock()
	s := st.sessions[id]
	delete(st.sessions, id)
	st.mu.Unlock()
	if s != nil {
		s.close()
	}
}

func (st *SessionStore) reap() {
	for range time.Tick(time.Minute) {
		cutoff := time.Now().Add(-st.idle)
		st.mu.Lock()
		var dead []*Session
		for id, s := range st.sessions {
			s.mu.Lock()
			last := s.lastUsed
			s.mu.Unlock()
			if last.Before(cutoff) {
				dead = append(dead, s)
				delete(st.sessions, id)
			}
		}
		st.mu.Unlock()
		for _, s := range dead {
			s.close()
		}
	}
}
