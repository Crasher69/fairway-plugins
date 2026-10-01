package main

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	fairway "github.com/Crasher69/fairway/plugin-sdk"
)

var now = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

// Ответ getproxy из документации proxy6.net (логины и пароли оттуда же).
const sampleGetproxy = `{"status":"yes","user_id":"1","balance":"48.80","currency":"RUB","list_count":2,"list":{
"11":{"id":"11","version":"6","ip":"2a00:1838:32:19f:45fb:2640::330","host":"185.22.134.250","port":"7330","user":"5svBNZ","pass":"iagn2d","type":"http","country":"ru","date":"2016-06-19 16:32:39","date_end":"2016-07-12 11:50:41","unixtime":1466379159,"unixtime_end":1468349441,"descr":"","active":"1"},
"14":{"id":"14","version":"4","ip":"185.22.134.242","host":"185.22.134.242","port":"7386","user":"nV5TFK","pass":"3Itr1t","type":"socks","country":"ru","date":"2016-06-27 16:06:22","date_end":"2016-07-11 16:06:22","unixtime":1466379151,"unixtime_end":1468253182,"descr":"","active":"1"}}}`

func TestParseGetproxy(t *testing.T) {
	var page proxyPage
	if err := json.Unmarshal([]byte(sampleGetproxy), &page); err != nil {
		t.Fatal(err)
	}
	if _, err := checkEnvelope("getproxy", []byte(sampleGetproxy)); err != nil {
		t.Fatal(err)
	}
	if page.Balance != 48.8 || page.Currency != "RUB" || page.ListCount != 2 {
		t.Fatalf("ответ %+v", page)
	}
	list, err := parseList(page.List)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != 11 || list[1].ID != 14 {
		t.Fatalf("список %+v", list)
	}
	p := list[0]
	if p.Version != 6 || p.Port != 7330 || p.address() != "185.22.134.250" || p.User != "5svBNZ" {
		t.Fatalf("прокси %+v", p)
	}
	end, err := p.end()
	if err != nil || !end.Equal(time.Unix(1468349441, 0)) {
		t.Fatalf("окончание %s %v", end, err)
	}
	if got := toProxy(list[1], "http", stateActive, end); got.Scheme != "socks5" || got.Host != "185.22.134.242" || got.Port != 7386 {
		t.Fatalf("socks %+v", got)
	}
}

func TestParseEmptyList(t *testing.T) {
	for _, raw := range []string{`[]`, `{}`, `null`, ``} {
		list, err := parseList(json.RawMessage(raw))
		if err != nil || len(list) != 0 {
			t.Fatalf("%q: %v %v", raw, list, err)
		}
	}
}

func TestEnvelopeError(t *testing.T) {
	_, err := checkEnvelope("getproxy", []byte(`{"status":"no","error_id":100,"error":"Error key"}`))
	var e *apiError
	if !errors.As(err, &e) || e.ID != 100 {
		t.Fatalf("ошибка %v", err)
	}
	if err.Error() != "proxy6 getproxy: error 100: Error key (wrong API key)" {
		t.Fatalf("текст %q", err)
	}
}

// proxy — прокси сервиса, который заканчивается через days дней (в
// прошлом — отрицательное).
func proxy(id int64, days float64) apiProxy {
	end := now.Add(time.Duration(days * 24 * float64(time.Hour)))
	return apiProxy{ID: num(id), Version: 4, IP: "10.0.0.1", Host: "10.0.0.1", Port: 8000, User: "u", Pass: "p",
		Type: "http", Country: "de", UnixtimeEnd: num(end.Unix())}
}

func defaults() settings { return settings{List: "proxy6", Scheme: "http", GraceDays: 3} }

func ids(proxies []fairway.Proxy) []string {
	var out []string
	for _, p := range proxies {
		out = append(out, p.ID)
	}
	return out
}

func listOf(lists []fairway.List, name string) []string {
	for _, l := range lists {
		if l.Name == name {
			return l.Proxies
		}
	}
	return nil
}

func TestPlanAddsActiveOnly(t *testing.T) {
	cfg := &fairway.Config{
		Proxies: []fairway.Proxy{{ID: "manual", Name: "manual", Host: "1.1.1.1", Port: 80}},
		Lists:   []fairway.List{{Name: "main", Proxies: []string{"manual"}}},
	}
	all := []apiProxy{proxy(2, 10), proxy(1, 5), proxy(3, -1), proxy(4, -10)}
	proxies, lists, r := plan(cfg, all, defaults(), now)

	if got := ids(proxies); !reflect.DeepEqual(got, []string{"manual", "proxy6-1", "proxy6-2"}) {
		t.Fatalf("прокси %v", got)
	}
	if got := listOf(lists, "proxy6"); !reflect.DeepEqual(got, []string{"proxy6-1", "proxy6-2"}) {
		t.Fatalf("лист %v", got)
	}
	if got := listOf(lists, "main"); !reflect.DeepEqual(got, []string{"manual"}) {
		t.Fatalf("чужой лист %v", got)
	}
	p := proxies[1]
	want := fairway.Proxy{ID: "proxy6-1", Name: "Германия-1", Scheme: "http", Host: "10.0.0.1", Port: 8000,
		Login: "u", Password: "p", Country: "DE", Comment: "proxy6 · до 2026-10-05"}
	if p != want {
		t.Fatalf("прокси\n%+v\nwant\n%+v", p, want)
	}
	if len(r.Added) != 2 || len(r.Removed) != 0 {
		t.Fatalf("отчёт %+v", r)
	}
}

// Протокол задан у прокси; настройка нужна только для auto.
func TestPlanSchemeAndNoList(t *testing.T) {
	s := defaults()
	s.Scheme, s.List = "socks5", ""
	a, b, c := proxy(1, 5), proxy(2, 5), proxy(3, 5)
	a.Type, b.Type, c.Type = "http", "socks", "auto"
	proxies, lists, _ := plan(&fairway.Config{}, []apiProxy{a, b, c}, s, now)
	var got []string
	for _, p := range proxies {
		got = append(got, p.Scheme)
	}
	if !reflect.DeepEqual(got, []string{"http", "socks5", "socks5"}) {
		t.Fatalf("протоколы %v", got)
	}
	if len(lists) != 0 {
		t.Fatalf("листы %v", lists)
	}
}

// Истёкший недавно остаётся где был; давно истёкший и пропавший из
// аккаунта уходят из листов и каталога.
func TestPlanExpiry(t *testing.T) {
	cfg := &fairway.Config{
		Proxies: []fairway.Proxy{
			{ID: "manual", Name: "manual"},
			{ID: "proxy6-1", Name: "my-name", Comment: "x"},
			{ID: "proxy6-2", Name: "b"},
			{ID: "proxy6-4", Name: "d"},
		},
		Lists: []fairway.List{
			{Name: "main", Proxies: []string{"manual", "proxy6-1", "proxy6-2", "proxy6-4"}},
			{Name: "other", Proxies: []string{"proxy6-2", "manual"}},
		},
	}
	// proxy6-4 сервис не вернул вовсе.
	proxies, lists, r := plan(cfg, []apiProxy{proxy(1, -2), proxy(2, -4)}, defaults(), now)

	if got := ids(proxies); !reflect.DeepEqual(got, []string{"manual", "proxy6-1"}) {
		t.Fatalf("прокси %v", got)
	}
	if got := listOf(lists, "main"); !reflect.DeepEqual(got, []string{"manual", "proxy6-1"}) {
		t.Fatalf("main %v", got)
	}
	if got := listOf(lists, "other"); !reflect.DeepEqual(got, []string{"manual"}) {
		t.Fatalf("other %v", got)
	}
	if proxies[1].Name != "my-name" || proxies[1].Comment != "proxy6 · истёк 2026-09-28" {
		t.Fatalf("истёкший %+v", proxies[1])
	}
	if len(r.Removed) != 2 || len(r.Updated) != 1 {
		t.Fatalf("отчёт %+v", r)
	}
}

// Лист, в котором не осталось бы ни одного прокси, fairway не примет:
// он остаётся как был вместе со своими прокси.
func TestPlanKeepsLastInList(t *testing.T) {
	cfg := &fairway.Config{
		Proxies: []fairway.Proxy{{ID: "proxy6-1", Name: "a"}, {ID: "proxy6-2", Name: "b"}},
		Lists: []fairway.List{
			{Name: "only", Proxies: []string{"proxy6-1"}},
			{Name: "mixed", Proxies: []string{"proxy6-1", "proxy6-2"}},
		},
	}
	proxies, lists, r := plan(cfg, []apiProxy{proxy(1, -10), proxy(2, 10)}, defaults(), now)
	if got := ids(proxies); !reflect.DeepEqual(got, []string{"proxy6-1", "proxy6-2"}) {
		t.Fatalf("прокси %v", got)
	}
	if got := listOf(lists, "only"); !reflect.DeepEqual(got, []string{"proxy6-1"}) {
		t.Fatalf("only %v", got)
	}
	if got := listOf(lists, "mixed"); !reflect.DeepEqual(got, []string{"proxy6-2"}) {
		t.Fatalf("mixed %v", got)
	}
	if len(r.Kept) != 1 || len(r.Warnings) != 1 {
		t.Fatalf("отчёт %+v", r)
	}
}

// Пустой ответ сервиса ничего не удаляет, а прокси без даты окончания
// остаётся как был.
func TestPlanSafety(t *testing.T) {
	cfg := &fairway.Config{
		Proxies: []fairway.Proxy{{ID: "proxy6-1", Name: "a"}, {ID: "proxy6-2", Name: "b"}},
		Lists:   []fairway.List{{Name: "l", Proxies: []string{"proxy6-1", "proxy6-2"}}},
	}
	proxies, lists, _ := plan(cfg, nil, defaults(), now)
	if !reflect.DeepEqual(proxies, cfg.Proxies) || !reflect.DeepEqual(lists, cfg.Lists) {
		t.Fatalf("пустой ответ поменял конфиг: %v %v", proxies, lists)
	}

	bad := proxy(1, 5)
	bad.UnixtimeEnd = 0
	proxies, _, r := plan(cfg, []apiProxy{bad, proxy(2, 5)}, defaults(), now)
	if got := ids(proxies); !reflect.DeepEqual(got, []string{"proxy6-1", "proxy6-2"}) {
		t.Fatalf("прокси %v", got)
	}
	if len(r.Warnings) != 1 {
		t.Fatalf("отчёт %+v", r)
	}
}

func TestPlanNameCollision(t *testing.T) {
	cfg := &fairway.Config{Proxies: []fairway.Proxy{{ID: "x", Name: "Германия-1"}}}
	proxies, _, _ := plan(cfg, []apiProxy{proxy(1, 5)}, defaults(), now)
	if proxies[1].Name != "Германия-1-2" {
		t.Fatalf("имя %q", proxies[1].Name)
	}
}

func TestParseSettings(t *testing.T) {
	s, every, err := parseSettings(json.RawMessage(`{"api_key":" k "}`))
	if err != nil || s.APIKey != "k" || every != 10*time.Minute || s.GraceDays != 3 || s.List != "proxy6" {
		t.Fatalf("%+v %s %v", s, every, err)
	}
	for _, raw := range []string{`{}`, `{"api_key":"k","scheme":"ftp"}`, `{"api_key":"k","interval":"10s"}`, `{"api_key":"a/b"}`} {
		if _, _, err := parseSettings(json.RawMessage(raw)); err == nil {
			t.Fatalf("%s: нет ошибки", raw)
		}
	}
}

func TestRedact(t *testing.T) {
	got := redact(`Get "https://px6.link/api/secret/getproxy/": timeout`, "secret")
	if got != `Get "https://px6.link/api/***/getproxy/": timeout` {
		t.Fatalf("%q", got)
	}
}

func TestPlanAdoptsManualProxy(t *testing.T) {
	// Руками добавлен прокси 1 и прокси 2, который плагин уже успел
	// добавить сам — дубль.
	p1, p2 := proxy(1, 5), proxy(2, 5)
	p1.Host, p2.Host = "10.0.0.1", "10.0.0.2"
	own2 := toProxy(p2, "http", stateActive, now.AddDate(0, 0, 5))
	own2.Name = "Германия-2"
	cfg := &fairway.Config{
		Proxies: []fairway.Proxy{
			{ID: "m1", Name: "руками", Host: "10.0.0.1", Port: 8000, Comment: "мой"},
			{ID: "m2", Name: "дубль", Host: "10.0.0.2", Port: 8000},
			own2,
		},
		Lists: []fairway.List{
			{Name: "main", Proxies: []string{"m1", "m2"}},
			{Name: "proxy6", Proxies: []string{"proxy6-2"}},
		},
	}
	proxies, lists, r := plan(cfg, []apiProxy{p1, p2}, defaults(), now)

	if got := ids(proxies); !reflect.DeepEqual(got, []string{"proxy6-1", "proxy6-2"}) {
		t.Fatalf("прокси %v", got)
	}
	if a := proxies[0]; a.Name != "Германия-1" || a.Comment != "proxy6 · до 2026-10-05" {
		t.Fatalf("забранный %+v", a)
	}
	if got := listOf(lists, "main"); !reflect.DeepEqual(got, []string{"proxy6-1", "proxy6-2"}) {
		t.Fatalf("main %v", got)
	}
	if !reflect.DeepEqual(r.Adopted, []string{"m1 → proxy6-1"}) || !reflect.DeepEqual(r.Merged, []string{"m2 → proxy6-2"}) ||
		len(r.Added) > 0 || len(r.Updated) > 0 {
		t.Fatalf("отчёт %+v", r)
	}

	cfg = &fairway.Config{Proxies: proxies, Lists: lists}
	if _, _, r = plan(cfg, []apiProxy{p1, p2}, defaults(), now); r.changed() {
		t.Fatalf("повтор %+v", r)
	}
}
