package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// settings — настройки плагина (settings_schema в manifest.json).
type settings struct {
	APIKey string `json:"api_key"`
	// List — лист, в который попадают новые прокси. Пусто — только в
	// каталог прокси.
	List   string `json:"list"`
	Scheme string `json:"scheme"`
	// Interval — как часто синхронизироваться.
	Interval string `json:"interval"`
	// GraceDays — сколько дней после окончания прокси не трогать.
	GraceDays int `json:"grace_days"`
	// ViaFairway — ходить в API через прокси самого fairway.
	ViaFairway bool `json:"via_fairway"`
	// DirectFallback — если через fairway не вышло (ошибка сети),
	// повторить напрямую.
	DirectFallback bool `json:"direct_fallback"`
}

// minInterval — у API лимит 50 запросов в минуту; синхронизация тратит
// минимум два, продление ещё два.
const minInterval = time.Minute

func parseSettings(raw json.RawMessage) (settings, time.Duration, error) {
	s := settings{List: "spaceproxy", Scheme: "http", Interval: "10m", GraceDays: 3}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &s); err != nil {
			return s, 0, err
		}
	}
	s.APIKey = strings.TrimSpace(s.APIKey)
	s.List = strings.TrimSpace(s.List)
	if s.APIKey == "" {
		return s, 0, fmt.Errorf("api_key is not set")
	}
	if s.Scheme != "http" && s.Scheme != "socks5" {
		return s, 0, fmt.Errorf("scheme must be http or socks5, not %q", s.Scheme)
	}
	if s.GraceDays < 0 {
		return s, 0, fmt.Errorf("grace_days must not be negative")
	}
	every, err := time.ParseDuration(s.Interval)
	if err != nil {
		return s, 0, fmt.Errorf("interval: %w", err)
	}
	if every < minInterval {
		return s, 0, fmt.Errorf("interval %s is shorter than %s", every, minInterval)
	}
	return s, every, nil
}

// apiProxy — прокси в ответе /api/proxies/.
type apiProxy struct {
	ID         int64  `json:"id"`
	IP         string `json:"ip"`
	PortHTTP   int    `json:"port_http"`
	PortSocks5 int    `json:"port_socks5"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Country    string `json:"country"`
	Type       string `json:"type"`
	IPVersion  int    `json:"ip_version"`
	Date       string `json:"date"`
	DateEnd    string `json:"date_end"`
	OrderID    int64  `json:"order_id"`
}

// apiPage — страница /api/proxies/.
type apiPage struct {
	Count   int        `json:"count"`
	Results []apiProxy `json:"results"`
}

// parseTime разбирает даты API: они приходят и как
// "2020-10-30 11:04:43.136000+00:00", и как "2020-11-29T14:04:42.770000+03:00".
func parseTime(s string) (time.Time, error) {
	s = strings.Replace(strings.TrimSpace(s), " ", "T", 1)
	return time.Parse(time.RFC3339Nano, s)
}
