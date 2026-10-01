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

	"github.com/Crasher69/fairway-plugins/internal/countries"
)

const (
	// apiBase — к нему дописываются ключ и метод: .../api/<ключ>/getproxy/.
	apiBase = "https://px6.link/api/"
	// pageSize — сколько прокси просить на страницу getproxy (1000 — и
	// так значение по умолчанию).
	pageSize = 1000
	// renewPeriod — на сколько дней продлеваем.
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
			fairway.Logf("proxy6: sync every %s, list %q", every, s.List)
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
	all, env, err := fetchAll()
	if err != nil {
		return report{}, err
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
		fairway.Logf("proxy6: %s", r)
	}
	last = &snapshot{At: time.Now(), All: all, Balance: env.Balance, Currency: env.Currency, Report: r}
	return r, nil
}

// fetchAll забирает все страницы getproxy: и активные, и истёкшие.
func fetchAll() ([]apiProxy, envelope, error) {
	var all []apiProxy
	for page := 1; ; page++ {
		q := url.Values{"state": {"all"}, "page": {strconv.Itoa(page)}, "limit": {strconv.Itoa(pageSize)}}
		body, err := request("getproxy", q)
		if err != nil {
			return nil, envelope{}, err
		}
		var p proxyPage
		if err := json.Unmarshal(body, &p); err != nil {
			return nil, envelope{}, fmt.Errorf("proxy6 getproxy: %w", err)
		}
		list, err := parseList(p.List)
		if err != nil {
			return nil, envelope{}, fmt.Errorf("proxy6 getproxy: %w", err)
		}
		all = append(all, list...)
		if len(list) < pageSize || len(all) >= int(p.ListCount) {
			return all, p.envelope, nil
		}
	}
}

// request — вызов метода API. Ключ стоит в пути URL, поэтому из текста
// ошибок он вырезается.
func request(method string, q url.Values) ([]byte, error) {
	body, err := fetch(method, q)
	if err != nil {
		return nil, errors.New(redact(err.Error(), cfg.APIKey))
	}
	return body, nil
}

func fetch(method string, q url.Values) ([]byte, error) {
	u := apiBase + cfg.APIKey + "/" + method + "/"
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req := fairway.Request{
		Method:     "GET",
		URL:        u,
		Headers:    map[string][]string{"Accept": {"application/json"}},
		ViaFairway: cfg.ViaFairway,
	}
	resp, err := fairway.Fetch(req)
	if err != nil && cfg.ViaFairway && cfg.DirectFallback {
		fairway.Warnf("proxy6: via fairway failed (%s), trying directly", redact(err.Error(), cfg.APIKey))
		req.ViaFairway = false
		resp, err = fairway.Fetch(req)
	}
	if err != nil {
		return nil, err
	}
	if resp.Status/100 != 2 {
		return nil, fmt.Errorf("proxy6 %s: HTTP %d: %s", method, resp.Status, snippet(resp.Body))
	}
	if _, err := checkEnvelope(method, resp.Body); err != nil {
		return nil, err
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
	ID      int64  `json:"id"`
	Address string `json:"address"`
	Scheme  string `json:"scheme"`
	Country string `json:"country"`
	// CountryRU — название страны по-русски, для русской панели.
	CountryRU string   `json:"country_ru,omitempty"`
	Version   int64    `json:"version"`
	Kind      string   `json:"kind"` // IPv4, IPv4 Shared, IPv6
	Descr     string   `json:"descr,omitempty"`
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
	case "price":
		ids, err := parseIDs(params)
		if err != nil {
			return nil, err
		}
		return price(ids)
	case "renew":
		ids, err := parseIDs(params)
		if err != nil {
			return nil, err
		}
		return renew(ids)
	}
	return nil, fmt.Errorf("unknown method %q", method)
}

func parseIDs(params json.RawMessage) ([]int64, error) {
	var p struct {
		IDs []int64 `json:"ids"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	if len(p.IDs) == 0 {
		return nil, errors.New("no proxies selected")
	}
	return p.IDs, nil
}

// price — сколько будет стоить продление: getprice по каждому типу
// выбранных прокси. Это цена покупки на тот же срок, продление обычно
// стоит так же.
func price(ids []int64) (any, error) {
	if last == nil {
		return nil, errors.New("not synced yet")
	}
	version := make(map[int64]num, len(last.All))
	for _, p := range last.All {
		version[int64(p.ID)] = p.Version
	}
	count := make(map[num]int)
	for _, id := range ids {
		v, ok := version[id]
		if !ok {
			return nil, fmt.Errorf("proxy %d is not in the account", id)
		}
		count[v]++
	}
	var total money
	currency := last.Currency
	for v, n := range count {
		q := url.Values{"count": {strconv.Itoa(n)}, "period": {strconv.Itoa(renewPeriod)}, "version": {strconv.FormatInt(int64(v), 10)}}
		body, err := request("getprice", q)
		if err != nil {
			return nil, err
		}
		var r priceReply
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, fmt.Errorf("proxy6 getprice: %w", err)
		}
		total += r.Price
		if r.Currency != "" {
			currency = r.Currency
		}
	}
	return map[string]any{"price": total, "currency": currency, "count": len(ids), "period": renewPeriod}, nil
}

func renew(ids []int64) (any, error) {
	list := make([]string, len(ids))
	for i, id := range ids {
		list[i] = strconv.FormatInt(id, 10)
	}
	q := url.Values{"period": {strconv.Itoa(renewPeriod)}, "ids": {strings.Join(list, ",")}}
	body, err := request("prolong", q)
	if err != nil {
		return nil, err
	}
	var r prolongReply
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("proxy6 prolong: %w", err)
	}
	fairway.Logf("proxy6: renewed %d proxies for %d days, order %d, price %.2f %s", r.Count, renewPeriod, r.OrderID, float64(r.Price), r.Currency)
	// Продлённые сразу возвращаются в конфиг с новой датой.
	if _, err := syncNow(); err != nil {
		fairway.Warnf("proxy6: sync after renew: %v", err)
	}
	return map[string]any{"renewed": int64(r.Count), "order_id": int64(r.OrderID), "price": r.Price,
		"currency": r.Currency, "balance": r.Balance}, nil
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
		code := strings.ToUpper(p.Country)
		r := row{ID: int64(p.ID), Country: code, CountryRU: countries.RU[code], Version: int64(p.Version),
			Kind: versionName(p.Version), Descr: p.Descr, Scheme: scheme(p, cfg.Scheme),
			Address: fmt.Sprintf("%s:%d", p.address(), p.Port), Lists: member[fairwayID(p.ID)]}
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
	sort.Slice(rows, func(i, j int) bool { return rows[i].DateEnd < rows[j].DateEnd })
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
