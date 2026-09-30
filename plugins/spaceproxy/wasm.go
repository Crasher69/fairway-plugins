//go:build wasip1

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	fairway "github.com/Crasher69/fairway/plugin-sdk"
)

const (
	apiBase = "https://panel.spaceproxy.net/api/"
	// pageSize — максимум, который отдаёт /api/proxies/.
	pageSize = 2000
	// renewPeriod — на сколько дней продлеваем.
	renewPeriod = 30
)

var (
	cfg settings
	// last — последняя удачная выгрузка для страницы плагина.
	last *snapshot
	// lastErr — ошибка последней синхронизации.
	lastErr string
	// every — интервал из настроек. Первый тик приходит через firstTick,
	// чтобы прокси появились сразу после включения, а не через интервал:
	// в Init на сеть времени мало (30 с на всё).
	every time.Duration
	first = true
)

const firstTick = 10 * time.Second

type snapshot struct {
	At      time.Time  `json:"at"`
	Live    []apiProxy `json:"-"`
	Deleted []apiProxy `json:"-"`
	Report  report     `json:"report"`
}

func init() {
	fairway.Register(fairway.Plugin{
		Init: func(raw json.RawMessage) error {
			s, interval, err := parseSettings(raw)
			if err != nil {
				return err
			}
			cfg, every = s, interval
			fairway.Logf("spaceproxy: sync every %s, list %q, %s", every, s.List, s.Scheme)
			return fairway.Every(firstTick)
		},
		Tick: func() error {
			if first {
				first = false
				if err := fairway.Every(every); err != nil {
					return err
				}
			}
			_, err := syncNow()
			return err
		},
		Call: call,
	})
}

func syncNow() (report, error) {
	r, err := doSync()
	if err != nil {
		lastErr = err.Error()
		return r, err
	}
	lastErr = ""
	return r, nil
}

func doSync() (report, error) {
	live, err := fetchAll("exclude_deleted")
	if err != nil {
		return report{}, err
	}
	deleted, err := fetchAll("deleted")
	if err != nil {
		return report{}, err
	}
	current, err := fairway.GetConfig()
	if err != nil {
		return report{}, err
	}
	proxies, lists, r := plan(current, live, deleted, cfg, time.Now())
	for _, w := range r.Warnings {
		fairway.Warnf("%s", w)
	}
	if len(r.Added)+len(r.Updated)+len(r.Removed) > 0 {
		if _, err := fairway.EditConfig(fairway.ConfigEdit{Proxies: &proxies, Lists: &lists}); err != nil {
			return r, fmt.Errorf("config: %w", err)
		}
		fairway.Logf("spaceproxy: %s", r)
	}
	last = &snapshot{At: time.Now(), Live: live, Deleted: deleted, Report: r}
	return r, nil
}

// fetchAll забирает все страницы /api/proxies/ с данным статусом.
func fetchAll(status string) ([]apiProxy, error) {
	var all []apiProxy
	for offset := 0; ; offset += pageSize {
		q := url.Values{"status": {status}, "limit": {strconv.Itoa(pageSize)}, "offset": {strconv.Itoa(offset)}}
		body, err := request("GET", "proxies/?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		var page apiPage
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("proxies: %w", err)
		}
		all = append(all, page.Results...)
		if len(page.Results) < pageSize || len(all) >= page.Count {
			return all, nil
		}
	}
}

// request — запрос к API. Ключ идёт заголовком, а не в URL: так он не
// попадёт в текст ошибки и в лог.
func request(method, path string, form url.Values) ([]byte, error) {
	req := fairway.Request{
		Method:     method,
		URL:        apiBase + path,
		Headers:    map[string][]string{"Api-Key": {cfg.APIKey}, "Accept": {"application/json"}},
		ViaFairway: cfg.ViaFairway,
	}
	if form != nil {
		req.Headers["Content-Type"] = []string{"application/x-www-form-urlencoded"}
		req.Body = []byte(form.Encode())
	}
	resp, err := fairway.Fetch(req)
	if err != nil && cfg.ViaFairway && cfg.DirectFallback {
		fairway.Warnf("spaceproxy: via fairway failed (%v), trying directly", err)
		req.ViaFairway = false
		resp, err = fairway.Fetch(req)
	}
	if err != nil {
		return nil, err
	}
	if resp.Status/100 != 2 {
		return nil, fmt.Errorf("%s %s: HTTP %d: %s", method, strings.SplitN(path, "?", 2)[0], resp.Status, snippet(resp.Body))
	}
	return resp.Body, nil
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// row — прокси на странице плагина.
type row struct {
	ID       int64    `json:"id"`
	Address  string   `json:"address"`
	Country  string   `json:"country"`
	IPv      int      `json:"ipv"`
	DateEnd  string   `json:"date_end"`
	DaysLeft float64  `json:"days_left"`
	State    string   `json:"state"` // active, grace, gone
	Lists    []string `json:"lists"`
}

func call(method string, params json.RawMessage) (any, error) {
	switch method {
	case "list":
		if last == nil {
			if _, err := syncNow(); err != nil {
				return nil, err
			}
		}
		return listView()
	case "sync":
		if _, err := syncNow(); err != nil {
			return nil, err
		}
		return listView()
	case "balance":
		body, err := request("GET", "balance/", nil)
		if err != nil {
			return nil, err
		}
		var b balance
		if err := json.Unmarshal(body, &b); err != nil {
			return nil, fmt.Errorf("balance: %w", err)
		}
		return b, nil
	case "renew":
		var p struct {
			IDs []int64 `json:"ids"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		if len(p.IDs) == 0 {
			return nil, errors.New("no proxies selected")
		}
		form := url.Values{"period": {strconv.Itoa(renewPeriod)}}
		for _, id := range p.IDs {
			form.Add("proxies", strconv.FormatInt(id, 10))
		}
		body, err := request("POST", "renew/", form)
		if err != nil {
			return nil, err
		}
		fairway.Logf("spaceproxy: renewed %d proxies for %d days: %s", len(p.IDs), renewPeriod, snippet(body))
		// Продлённые сразу возвращаются в конфиг с новой датой.
		if _, err := syncNow(); err != nil {
			fairway.Warnf("spaceproxy: sync after renew: %v", err)
		}
		return map[string]any{"renewed": len(p.IDs), "response": json.RawMessage(orNull(body))}, nil
	}
	return nil, fmt.Errorf("unknown method %q", method)
}

func orNull(b []byte) []byte {
	if !json.Valid(b) {
		out, _ := json.Marshal(string(b))
		return out
	}
	return b
}

func listView() (any, error) {
	current, err := fairway.GetConfig()
	if err != nil {
		return nil, err
	}
	member := make(map[string][]string)
	for _, l := range current.Lists {
		for _, id := range l.Proxies {
			member[id] = append(member[id], l.Name)
		}
	}
	now := time.Now()
	rows := make([]row, 0, len(last.Live))
	for _, p := range last.Live {
		st, end, err := classify(p, now, cfg.GraceDays)
		r := row{ID: p.ID, Country: strings.ToUpper(p.Country), IPv: p.IPVersion,
			Lists: member[fairwayID(p.ID)]}
		port := p.PortHTTP
		if cfg.Scheme == "socks5" {
			port = p.PortSocks5
		}
		r.Address = fmt.Sprintf("%s:%d", p.IP, port)
		if err == nil {
			r.DateEnd = end.UTC().Format(time.RFC3339)
			r.DaysLeft = end.Sub(now).Hours() / 24
			r.State = [...]string{"active", "grace", "gone"}[st]
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].DateEnd < rows[j].DateEnd })
	return map[string]any{
		"synced_at":  last.At,
		"error":      lastErr,
		"report":     last.Report,
		"grace_days": cfg.GraceDays,
		"period":     renewPeriod,
		"proxies":    rows,
	}, nil
}
