package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// settings — настройки плагина (settings_schema в manifest.json).
type settings struct {
	APIKey string `json:"api_key"`
	// List — лист, в который попадают новые прокси. Пусто — только в
	// каталог прокси.
	List string `json:"list"`
	// Scheme — протокол для прокси с типом auto (у них HTTP и SOCKS5 на
	// одном порту). У остальных протокол задан в proxy6.
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

// minInterval — чаще синхронизироваться незачем; лимит API — 3 запроса в
// секунду.
const minInterval = time.Minute

func parseSettings(raw json.RawMessage) (settings, time.Duration, error) {
	s := settings{List: "proxy6", Scheme: "http", Interval: "10m", GraceDays: 3}
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
	// Ключ идёт в путь URL: чужие символы сломали бы запрос.
	if strings.ContainsAny(s.APIKey, "/?#% ") {
		return s, 0, fmt.Errorf("api_key contains invalid characters")
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

// num — число, которое API отдаёт то строкой ("11"), то числом.
type num int64

func (n *num) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*n = 0
		return nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("not a number: %s", b)
	}
	*n = num(v)
	return nil
}

// money — сумма, которую API отдаёт то строкой ("48.80"), то числом.
type money float64

func (m *money) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*m = 0
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("not a number: %s", b)
	}
	*m = money(v)
	return nil
}

// apiProxy — прокси в ответе getproxy и prolong.
type apiProxy struct {
	ID num `json:"id"`
	// Version — 4 (IPv4), 3 (IPv4 Shared), 6 (IPv6).
	Version num `json:"version"`
	// IP — выходной адрес; Host — куда подключаться (у IPv6-прокси
	// они разные).
	IP   string `json:"ip"`
	Host string `json:"host"`
	Port num    `json:"port"`
	User string `json:"user"`
	Pass string `json:"pass"`
	// Type — http, socks или auto (оба на одном порту).
	Type    string `json:"type"`
	Country string `json:"country"`
	// DateEnd — строка без часового пояса; верим UnixtimeEnd.
	DateEnd     string `json:"date_end"`
	UnixtimeEnd num    `json:"unixtime_end"`
	Descr       string `json:"descr"`
	Active      num    `json:"active"`
}

func (p apiProxy) end() (time.Time, error) {
	if p.UnixtimeEnd <= 0 {
		return time.Time{}, fmt.Errorf("proxy %d: no unixtime_end", p.ID)
	}
	return time.Unix(int64(p.UnixtimeEnd), 0).UTC(), nil
}

// address — куда подключаться.
func (p apiProxy) address() string {
	if p.Host != "" {
		return p.Host
	}
	return p.IP
}

// envelope — общие поля любого ответа API.
type envelope struct {
	Status   string `json:"status"`
	ErrorID  int    `json:"error_id"`
	Error    string `json:"error"`
	Balance  money  `json:"balance"`
	Currency string `json:"currency"`
}

// apiError — ответ со status "no".
type apiError struct {
	Method string
	ID     int
	Text   string
}

func (e *apiError) Error() string {
	msg := fmt.Sprintf("proxy6 %s: error %d: %s", e.Method, e.ID, e.Text)
	switch e.ID {
	case 100:
		msg += " (wrong API key)"
	case 105:
		msg += " (API access is limited by IP in proxy6 settings)"
	case 400:
		msg += " (not enough money on the balance)"
	}
	return msg
}

// checkEnvelope разбирает общие поля ответа и превращает status "no" в
// ошибку.
func checkEnvelope(method string, body []byte) (envelope, error) {
	var e envelope
	if err := json.Unmarshal(body, &e); err != nil {
		return e, fmt.Errorf("proxy6 %s: %w", method, err)
	}
	if e.Status != "yes" {
		return e, &apiError{Method: method, ID: e.ErrorID, Text: e.Error}
	}
	return e, nil
}

// proxyPage — ответ getproxy.
type proxyPage struct {
	envelope
	ListCount num             `json:"list_count"`
	List      json.RawMessage `json:"list"`
}

// parseList разбирает поле list: объект по id ({"11":{...}}), а пустой —
// часто пустой массив ([]).
func parseList(raw json.RawMessage) ([]apiProxy, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var out []apiProxy
	if raw[0] == '[' {
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("list: %w", err)
		}
	} else {
		var m map[string]apiProxy
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("list: %w", err)
		}
		for _, p := range m {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// priceReply — ответ getprice.
type priceReply struct {
	envelope
	Price       money `json:"price"`
	PriceSingle money `json:"price_single"`
}

// prolongReply — ответ prolong.
type prolongReply struct {
	envelope
	OrderID num             `json:"order_id"`
	Price   money           `json:"price"`
	Count   num             `json:"count"`
	List    json.RawMessage `json:"list"`
}

// versionName — тип прокси для страницы.
func versionName(v num) string {
	switch v {
	case 3:
		return "IPv4 Shared"
	case 4:
		return "IPv4"
	case 6:
		return "IPv6"
	}
	return strconv.FormatInt(int64(v), 10)
}

// redact убирает ключ из текста: он идёт в путь URL и попадает в ошибки
// сети.
func redact(s, key string) string {
	if key == "" {
		return s
	}
	return strings.ReplaceAll(s, key, "***")
}
