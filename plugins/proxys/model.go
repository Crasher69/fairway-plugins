package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
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
	// Scheme — каким протоколом подключаться: у каждого IP свои порты
	// для HTTP и SOCKS5.
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

// minInterval — чаще синхронизироваться незачем.
const minInterval = time.Minute

func parseSettings(raw json.RawMessage) (settings, time.Duration, error) {
	s := settings{List: "proxys", Scheme: "http", Interval: "10m", GraceDays: 3}
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
	if strings.ContainsAny(s.APIKey, "/?#&% ") {
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

// num — число, которое API может отдать и строкой ("11"), и числом.
type num int64

func (n *num) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*n = 0
		return nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		f, ferr := strconv.ParseFloat(s, 64)
		if ferr != nil {
			return fmt.Errorf("not a number: %s", b)
		}
		v = int64(f)
	}
	*n = num(v)
	return nil
}

// money — сумма, строкой или числом.
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

// stamp — момент времени. По документации expires_at — unix-время
// (1493116222), но на случай даты строкой разбираем и её; строка без
// часового пояса считается UTC.
type stamp time.Time

var stampLayouts = []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999Z07:00", "2006-01-02 15:04:05", "2006-01-02T15:04:05", "2006-01-02"}

func (t *stamp) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*t = stamp{}
		return nil
	}
	if v, err := strconv.ParseInt(s, 10, 64); err == nil {
		*t = stamp(time.Unix(v, 0).UTC())
		return nil
	}
	for _, layout := range stampLayouts {
		if v, err := time.Parse(layout, s); err == nil {
			*t = stamp(v.UTC())
			return nil
		}
	}
	return fmt.Errorf("not a time: %s", b)
}

// apiIP — один IP заказа.
type apiIP struct {
	IP        string `json:"ip"`
	PortSocks num    `json:"port_socks"`
	PortHTTP  num    `json:"port_http"`
	PortHTTPS num    `json:"port_https"`
}

// apiOrder — заказ в ответе /ip: один логин и пароль, одна дата окончания
// и список IP.
type apiOrder struct {
	OrderID   num     `json:"order_id"`
	IPVersion string  `json:"ip_version"`
	Username  string  `json:"username"`
	Password  string  `json:"password"`
	IPAccess  string  `json:"ip_access"`
	ExpiresAt stamp   `json:"expires_at"`
	ListIP    []apiIP `json:"list_ip"`
	// Страны в документации у заказа нет; если API её отдаёт, берём.
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
}

// apiProxy — один IP заказа, как его видит плагин: прокси fairway.
type apiProxy struct {
	OrderID int64
	// N — номер IP в заказе с 1, по порядку адресов.
	N         int
	IP        string
	PortHTTP  int
	PortSocks int
	User      string
	Pass      string
	Country   string
	IPVersion string
	// End — окончание заказа; нулевое — дату не разобрать.
	End time.Time
}

func (p apiProxy) end() (time.Time, error) {
	if p.End.IsZero() {
		return p.End, fmt.Errorf("order %d: no expires_at", p.OrderID)
	}
	return p.End, nil
}

// flatten раскладывает заказы на прокси: по одному на IP. IP внутри
// заказа нумеруются по порядку адресов, чтобы номер не зависел от
// порядка в ответе.
func flatten(orders []apiOrder) []apiProxy {
	var out []apiProxy
	for _, o := range orders {
		ips := append([]apiIP(nil), o.ListIP...)
		sort.SliceStable(ips, func(i, j int) bool { return ips[i].IP < ips[j].IP })
		country := o.CountryCode
		if len(country) != 2 {
			country = o.Country
		}
		if len(country) != 2 {
			country = ""
		}
		for i, ip := range ips {
			out = append(out, apiProxy{
				OrderID: int64(o.OrderID), N: i + 1, IP: strings.TrimSpace(ip.IP),
				PortHTTP: int(ip.PortHTTP), PortSocks: int(ip.PortSocks),
				User: o.Username, Pass: o.Password, Country: strings.ToUpper(country),
				IPVersion: o.IPVersion, End: time.Time(o.ExpiresAt),
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].OrderID != out[j].OrderID {
			return out[i].OrderID < out[j].OrderID
		}
		return out[i].N < out[j].N
	})
	return out
}

// envelope — общие поля ответа: success, data и error.
type envelope struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   json.RawMessage `json:"error"`
}

// apiError — ответ с success false.
type apiError struct {
	Method string
	Code   int
	Text   string
}

func (e *apiError) Error() string {
	msg := fmt.Sprintf("proxys %s: error %d: %s", e.Method, e.Code, e.Text)
	switch e.Code {
	case 1000:
		msg += " (wrong API key)"
	case 1001:
		msg += " (API key expired)"
	case 1003:
		msg += " (order status does not allow renewal)"
	case 1004:
		msg += " (not enough money on the balance)"
	}
	return msg
}

// checkEnvelope разбирает ответ и превращает success false в ошибку.
// Ошибка — объект {code, message}, но на всякий случай понимает и строку.
func checkEnvelope(method string, body []byte) (json.RawMessage, error) {
	var e envelope
	if err := json.Unmarshal(body, &e); err != nil {
		return nil, fmt.Errorf("proxys %s: %w", method, err)
	}
	if e.Success {
		return e.Data, nil
	}
	ae := &apiError{Method: method}
	raw := bytes.TrimSpace(e.Error)
	if len(raw) > 0 && raw[0] == '{' {
		var obj struct {
			Code    num             `json:"code"`
			Message json.RawMessage `json:"message"`
		}
		if json.Unmarshal(raw, &obj) == nil {
			ae.Code = int(obj.Code)
			ae.Text = messageText(obj.Message)
		}
	} else if len(raw) > 0 {
		ae.Text = messageText(raw)
	}
	if ae.Text == "" {
		ae.Text = "request failed"
	}
	return nil, ae
}

// messageText — текст ошибки: строка, а у ошибок проверки — объект или
// массив сообщений.
func messageText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return strings.TrimSpace(string(raw))
}

// parseOrders разбирает data ответа /ip: массив заказов или один заказ.
func parseOrders(raw json.RawMessage) ([]apiOrder, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	if raw[0] == '[' {
		var out []apiOrder
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("orders: %w", err)
		}
		return out, nil
	}
	var one apiOrder
	if err := json.Unmarshal(raw, &one); err != nil {
		return nil, fmt.Errorf("orders: %w", err)
	}
	if one.OrderID == 0 && len(one.ListIP) == 0 {
		return nil, nil
	}
	return []apiOrder{one}, nil
}

// balanceReply — data ответа /balance.
type balanceReply struct {
	UserBalance money  `json:"user_balance"`
	Currency    string `json:"currency"`
}

// extendReply — data ответа /extending.
type extendReply struct {
	OrderID   num    `json:"order_id"`
	Price     money  `json:"price"`
	Currency  string `json:"currency"`
	ExpiresAt stamp  `json:"expires_at"`
}

// redact убирает ключ из текста: он идёт в адрес запроса и попадает в
// ошибки сети (в том числе в закодированном виде).
func redact(s, key string) string {
	if key == "" {
		return s
	}
	s = strings.ReplaceAll(s, key, "***")
	if esc := url.QueryEscape(key); esc != key {
		s = strings.ReplaceAll(s, esc, "***")
	}
	return s
}
