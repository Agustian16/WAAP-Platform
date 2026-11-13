package correlate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Agustian16/WAAP-Platform/server/internal/model"
)

// LiveStore holds the campaign each actor is currently building (FR-6.2 sliding window state).
type LiveStore interface {
	// Update runs fn on the actor's live campaign (nil when there is none) while holding a lock that excludes
	// every other writer for that actor, including other control plane instances. A non-nil result is stored.
	Update(ctx context.Context, actor string, fn func(*model.Campaign) (*model.Campaign, error)) error
	// Seed stores c unless the actor already has a live campaign (restore after a restart).
	Seed(ctx context.Context, c model.Campaign) error
}

// MemoryLive keeps live campaigns in this process. Only one control plane instance may correlate with it.
type MemoryLive struct {
	mu   sync.Mutex
	live map[string]*model.Campaign
}

func NewMemoryLive() *MemoryLive { return &MemoryLive{live: map[string]*model.Campaign{}} }

func (m *MemoryLive) Update(_ context.Context, actor string, fn func(*model.Campaign) (*model.Campaign, error)) error {
	m.mu.Lock() // ponytail: one lock for all actors; per-actor locks if a single instance ever saturates on it
	defer m.mu.Unlock()
	var cur *model.Campaign
	if c, ok := m.live[actor]; ok {
		cp := clone(*c)
		cur = &cp
	}
	out, err := fn(cur)
	if err == nil && out != nil {
		cp := clone(*out)
		m.live[actor] = &cp
	}
	return err
}

func (m *MemoryLive) Seed(_ context.Context, c model.Campaign) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cur, ok := m.live[c.ActorKey]; !ok || cur.LastSeen < c.LastSeen {
		cp := clone(c)
		m.live[c.ActorKey] = &cp
	}
	return nil
}

func clone(c model.Campaign) model.Campaign {
	c.Stages = append([]string{}, c.Stages...)
	c.Categories = append([]string{}, c.Categories...)
	c.Targets = append([]string{}, c.Targets...)
	c.ShellPaths = append([]string{}, c.ShellPaths...)
	c.Notes = append([]model.Note{}, c.Notes...)
	return c
}

// RedisLive shares live campaigns between control plane instances (NFR-3.2), so the same actor hitting nodes
// connected to different instances still builds one campaign.
type RedisLive struct {
	rdb *redis.Client
	ttl time.Duration // longer than the longest idle timeout (1440 min)
}

func NewRedisLive(rdb *redis.Client) *RedisLive { return &RedisLive{rdb: rdb, ttl: 25 * time.Hour} }

// liveRec carries the correlation-only fields that the API hides (json:"-" on model.Campaign).
type liveRec struct {
	model.Campaign
	SiteID     string   `json:"site_id"`
	Categories []string `json:"categories"`
	ShellPaths []string `json:"shell_paths"`
	Opened     bool     `json:"opened"`
}

func encode(c model.Campaign) ([]byte, error) {
	return json.Marshal(liveRec{Campaign: c, SiteID: c.SiteID, Categories: c.Categories, ShellPaths: c.ShellPaths, Opened: c.Opened})
}

func decode(b []byte) (*model.Campaign, error) {
	var r liveRec
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	c := r.Campaign
	c.SiteID, c.Categories, c.ShellPaths, c.Opened = r.SiteID, r.Categories, r.ShellPaths, r.Opened
	return &c, nil
}

var unlock = redis.NewScript(`if redis.call("GET", KEYS[1]) == ARGV[1] then return redis.call("DEL", KEYS[1]) end return 0`)

func (r *RedisLive) Update(ctx context.Context, actor string, fn func(*model.Campaign) (*model.Campaign, error)) error {
	key, lock := "corazium:live:"+actor, "corazium:lock:"+actor
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)
	deadline := time.Now().Add(5 * time.Second)
	for {
		// The lock expires on its own, so a crashed instance cannot block an actor for longer than 10 s.
		ok, err := r.rdb.SetNX(ctx, lock, token, 10*time.Second).Result()
		if err != nil {
			return fmt.Errorf("redis lock: %w", err)
		}
		if ok {
			break
		}
		if time.Now().After(deadline) {
			return errors.New("redis lock: timed out waiting for another instance")
		}
		time.Sleep(5 * time.Millisecond)
	}
	defer unlock.Run(context.WithoutCancel(ctx), r.rdb, []string{lock}, token)

	var cur *model.Campaign
	raw, err := r.rdb.Get(ctx, key).Bytes()
	switch {
	case errors.Is(err, redis.Nil):
	case err != nil:
		return fmt.Errorf("redis get: %w", err)
	default:
		if cur, err = decode(raw); err != nil {
			cur = nil // a corrupt entry is replaced, not fatal
		}
	}
	out, err := fn(cur)
	if err != nil || out == nil {
		return err
	}
	enc, err := encode(*out)
	if err != nil {
		return err
	}
	return r.rdb.Set(ctx, key, enc, r.ttl).Err()
}

func (r *RedisLive) Seed(ctx context.Context, c model.Campaign) error {
	enc, err := encode(c)
	if err != nil {
		return err
	}
	return r.rdb.SetNX(ctx, "corazium:live:"+c.ActorKey, enc, r.ttl).Err()
}
