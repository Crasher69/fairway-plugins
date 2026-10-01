//go:build wasip1

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	fairway "github.com/Crasher69/fairway/plugin-sdk"

	"github.com/Crasher69/fairway-plugins/internal/countries"
)

const (
	// apiBase — к нему дописывается метод: .../api/v2/ip?key=...
	apiBase = "https://proxys.world/api/v2/"
	// renewPeriod — на сколько дней продлевает /extending; другого срока
	// API не предлагает.
	renewPeriod = 30
	// hideAfterDays — истёкшие дольше этого на странице не показываем:
	// продлевать их уже никто не будет.
	hideAfterDays = 7
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
	At       time.Time
	All      []apiProxy
	Balance  money
	Currency string
	Report   report
}

func init() {
	fairway.Register(fairway.Plugin{
		Init: func(raw json.RawMessage) error {
			s, interval, err := parseSettings(raw)
			if err != nil {
				return err
			}
			cfg, every = s, interval
			fairway.Logf("proxys: sync every %s, list %q", every, s.List)
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
	all, err := fetchAll()
	if err != nil {
		return report{}, err
	}
	// Баланс — отдельный запрос; без него синхронизация всё равно идёт.
	bal, balErr := fetchBalance()
	if balErr != nil {
		fairway.Warnf("proxys: balance: %v", balErr)
	}
	current, err := fairway.GetConfig()
	if err != nil {
		return report{}, err
	}
	proxies, lists, r := plan(current, all, cfg, time.Now())
	for _, w := range r.Warnings {
		fairway.Warnf("%s", w)
	}
	if r.changed() {
		if _, err := fairway.EditConfig(fairway.ConfigEdit{Proxies: &proxies, Lists: &lists}); err != nil {
			return r, fmt.Errorf("config: %w", err)
		}
		fairway.Logf("proxys: %s", r)
	}
	last = &snapshot{At: time.Now(), All: all, Balance: bal.UserBalance, Currency: bal.Currency, Report: r}
	return r, nil
}

// fetchAll — IP всех заказов аккаунта.
func fetchAll() ([]apiProxy, error) {
	data, err := request("GET", "ip", nil)
	if err != nil {
		return nil, err
	}
	orders, err := parseOrders(data)
	if err != nil {
		return nil, fmt.Errorf("proxys ip: %w", err)
	}
	return flatten(orders), nil
}

func fetchBalance() (balanceReply, error) {
	var b balanceReply
	data, err := request("GET", "balance", nil)
	if err != nil {
		return b, err
	}
	if err := json.Unmarshal(data, &b); err != nil {
		return b, fmt.Errorf("proxys balance: %w", err)
	}
	return b, nil
}

// request — вызов метода API, возвращает data ответа. Ключ стоит в адресе
// (и в теле POST), поэтому из текста ошибок он вырезается.
func request(httpMethod, method string, body map[string]any) (json.RawMessage, error) {
	data, err := fetch(httpMethod, method, body)
	if err != nil {
		return nil, errors.New(redact(err.Error(), cfg.APIKey))
	}
	return data, nil
}

func fetch(httpMethod, method string, body map[string]any) (json.RawMessage, error) {
	req := fairway.Request{
		Method:     httpMethod,
		URL:        apiBase + method + "?" + url.Values{"key": {cfg.APIKey}}.Encode(),
		Headers:    map[string][]string{"Accept": {"application/json"}},
		ViaFairway: cfg.ViaFairway,
	}
	if body != nil {
		body["key"] = cfg.APIKey
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		req.Body = b
		req.Headers["Content-Type"] = []string{"application/json"}
	}
	resp, err := fairway.Fetch(req)
	if err != nil && cfg.ViaFairway && cfg.DirectFallback {
		fairway.Warnf("proxys: via fairway failed (%s), trying directly", redact(err.Error(), cfg.APIKey))
		req.ViaFairway = false
		resp, err = fairway.Fetch(req)
	}
	if err != nil {
		return nil, err
	}
	data, err := checkEnvelope(method, resp.Body)
	var ae *apiError
	if errors.As(err, &ae) {
		// Ошибка API приходит и с кодом 4xx: её текст полезнее кода.
		return nil, err
	}
	// /ip по ключу пользователя отвечает 201 — тоже успех.
	if resp.Status/100 != 2 {
		return nil, fmt.Errorf("proxys %s: HTTP %d: %s", method, resp.Status, snippet(resp.Body))
	}
	return data, err
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
	ID      string `json:"id"`
	OrderID int64  `json:"order_id"`
	Address string `json:"address"`
	Scheme  string `json:"scheme"`
	Country string `json:"country"`
	// CountryRU — название страны по-русски, для русской панели.
	CountryRU string   `json:"country_ru,omitempty"`
	Kind      string   `json:"kind"` // ip_version из API
	DateEnd   string   `json:"date_end"`
	DaysLeft  float64  `json:"days_left"`
	State     string   `json:"state"` // active, grace, gone
	Lists     []string `json:"lists"`
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
	case "renew":
		var p struct {
			Orders []int64 `json:"orders"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		if len(p.Orders) == 0 {
			return nil, errors.New("no orders selected")
		}
		return renew(p.Orders)
	}
	return nil, fmt.Errorf("unknown method %q", method)
}

// renew продлевает заказы по одному: /extending берёт один заказ и всегда
// продлевает на 30 дней. На первой ошибке останавливается и сообщает,
// что успело продлиться.
func renew(orders []int64) (any, error) {
	var total money
	currency := ""
	var done []int64
	var failed error
	for _, id := range orders {
		// В схеме Extending обязательное поле названо order, а описано
		// order_id: шлём оба.
		data, err := request("POST", "extending", map[string]any{"order_id": id, "order": id})
		if err != nil {
			failed = err
			break
		}
		var r extendReply
		if err := json.Unmarshal(data, &r); err != nil {
			failed = fmt.Errorf("proxys extending: %w", err)
			break
		}
		total += r.Price
		if r.Currency != "" {
			currency = r.Currency
		}
		done = append(done, id)
		fairway.Logf("proxys: renewed order %d for %d days, price %.2f %s", id, renewPeriod, float64(r.Price), r.Currency)
	}
	// Продлённые сразу возвращаются в конфиг с новой датой.
	if len(done) > 0 {
		if _, err := syncNow(); err != nil {
			fairway.Warnf("proxys: sync after renew: %v", err)
		}
	}
	if failed != nil {
		if len(done) == 0 {
			return nil, failed
		}
		return nil, fmt.Errorf("renewed orders %v, then: %w", done, failed)
	}
	res := map[string]any{"renewed": len(done), "price": total, "currency": currency}
	if last != nil {
		res["balance"] = last.Balance
	}
	return res, nil
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
	rows := make([]row, 0, len(last.All))
	for _, p := range last.All {
		st, end, err := classify(p, now, cfg.GraceDays)
		sc := p.scheme(cfg.Scheme)
		r := row{ID: serviceID(p), OrderID: p.OrderID, Country: p.Country, CountryRU: countries.RU[p.Country],
			Kind: ipVersionName(p.IPVersion), Scheme: sc, Address: fmt.Sprintf("%s:%d", p.IP, p.port(sc)), Lists: member[fairwayID(p)]}
		if err == nil {
			if now.Sub(end) > hideAfterDays*24*time.Hour {
				continue
			}
			r.DateEnd = end.Format(time.RFC3339)
			r.DaysLeft = end.Sub(now).Hours() / 24
			r.State = [...]string{"active", "grace", "gone"}[st]
		}
		rows = append(rows, r)
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].DateEnd < rows[j].DateEnd })
	return map[string]any{
		"synced_at":  last.At,
		"error":      lastErr,
		"report":     last.Report,
		"grace_days": cfg.GraceDays,
		"period":     renewPeriod,
		"balance":    last.Balance,
		"currency":   last.Currency,
		"proxies":    rows,
	}, nil
}
