package main

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	fairway "github.com/Crasher69/fairway/plugin-sdk"
)

var now = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

// Кусок настоящего ответа /api/proxies/ (логины и пароли заменены).
const samplePage = `{"count":2,"next":null,"previous":null,"results":[
{"id":369160,"ip":"45.149.82.192","internal_ip":null,"port_http":57683,"port_socks5":50174,"user":"u1","username":"u1","password":"p1","order_id":87114,"type":"1","ip_version":4,"country":"us","date":"2020-10-30 11:04:43.136000+00:00","date_end":"2020-11-29T14:04:42.770000+03:00","tags":[],"access_ips":[]},
{"id":382691,"ip":"213.139.192.143","internal_ip":null,"port_http":55818,"port_socks5":52573,"user":"u2","username":"u2","password":"p2","order_id":91943,"type":"1","ip_version":4,"country":"us","date":"2020-11-13 09:07:42.875000+00:00","date_end":"2020-12-13T12:07:42.722000+03:00","tags":[],"access_ips":[]}]}`

func TestParsePage(t *testing.T) {
	var page apiPage
	if err := json.Unmarshal([]byte(samplePage), &page); err != nil {
		t.Fatal(err)
	}
	if page.Count != 2 || len(page.Results) != 2 {
		t.Fatalf("страница %+v", page)
	}
	p := page.Results[0]
	if p.ID != 369160 || p.PortSocks5 != 50174 || p.Username != "u1" || p.Country != "us" {
		t.Fatalf("прокси %+v", p)
	}
	for _, s := range []string{p.Date, p.DateEnd} {
		if _, err := parseTime(s); err != nil {
			t.Fatalf("дата %q: %v", s, err)
		}
	}
	end, _ := parseTime(p.DateEnd)
	if want := time.Date(2020, 11, 29, 11, 4, 42, 770000000, time.UTC); !end.Equal(want) {
		t.Fatalf("date_end %s, want %s", end, want)
	}
}

// proxy — прокси сервиса, который заканчивается через days дней (в
// прошлом — отрицательное).
func proxy(id int64, days float64) apiProxy {
	end := now.Add(time.Duration(days * 24 * float64(time.Hour)))
	return apiProxy{ID: id, IP: "10.0.0.1", PortHTTP: 8000, PortSocks5: 9000,
		Username: "u", Password: "p", Country: "de", DateEnd: end.Format("2006-01-02 15:04:05.000000-07:00")}
}

func defaults() settings { return settings{List: "spaceproxy", Scheme: "http", GraceDays: 3} }

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
	live := []apiProxy{proxy(2, 10), proxy(1, 5), proxy(3, -1), proxy(4, -10)}
	proxies, lists, r := plan(cfg, live, nil, defaults(), now)

	if got := ids(proxies); !reflect.DeepEqual(got, []string{"manual", "spaceproxy-1", "spaceproxy-2"}) {
		t.Fatalf("прокси %v", got)
	}
	if got := listOf(lists, "spaceproxy"); !reflect.DeepEqual(got, []string{"spaceproxy-1", "spaceproxy-2"}) {
		t.Fatalf("лист %v", got)
	}
	if got := listOf(lists, "main"); !reflect.DeepEqual(got, []string{"manual"}) {
		t.Fatalf("чужой лист %v", got)
	}
	p := proxies[1]
	want := fairway.Proxy{ID: "spaceproxy-1", Name: "spaceproxy-1", Scheme: "http", Host: "10.0.0.1", Port: 8000,
		Login: "u", Password: "p", Country: "DE", Comment: "spaceproxy · до 2026-10-05"}
	if p != want {
		t.Fatalf("прокси\n%+v\nwant\n%+v", p, want)
	}
	if len(r.Added) != 2 || len(r.Removed) != 0 {
		t.Fatalf("отчёт %+v", r)
	}
}

func TestPlanSocks5AndNoList(t *testing.T) {
	s := defaults()
	s.Scheme, s.List = "socks5", ""
	proxies, lists, _ := plan(&fairway.Config{}, []apiProxy{proxy(1, 5)}, nil, s, now)
	if proxies[0].Scheme != "socks5" || proxies[0].Port != 9000 {
		t.Fatalf("прокси %+v", proxies[0])
	}
	if len(lists) != 0 {
		t.Fatalf("листы %v", lists)
	}
}

// Истёкший недавно остаётся где был, давно истёкший и удалённый уходят
// из листов и каталога.
func TestPlanExpiry(t *testing.T) {
	cfg := &fairway.Config{
		Proxies: []fairway.Proxy{
			{ID: "manual", Name: "manual"},
			{ID: "spaceproxy-1", Name: "my-name", Comment: "x"},
			{ID: "spaceproxy-2", Name: "b"},
			{ID: "spaceproxy-3", Name: "c"},
			{ID: "spaceproxy-4", Name: "d"},
		},
		Lists: []fairway.List{
			{Name: "main", Proxies: []string{"manual", "spaceproxy-1", "spaceproxy-2", "spaceproxy-3", "spaceproxy-4"}},
			{Name: "other", Proxies: []string{"spaceproxy-2", "manual"}},
		},
	}
	live := []apiProxy{proxy(1, -2), proxy(2, -4)}
	deleted := []apiProxy{proxy(3, -100)}
	// spaceproxy-4 сервис не вернул вовсе.
	proxies, lists, r := plan(cfg, live, deleted, defaults(), now)

	if got := ids(proxies); !reflect.DeepEqual(got, []string{"manual", "spaceproxy-1"}) {
		t.Fatalf("прокси %v", got)
	}
	if got := listOf(lists, "main"); !reflect.DeepEqual(got, []string{"manual", "spaceproxy-1"}) {
		t.Fatalf("main %v", got)
	}
	if got := listOf(lists, "other"); !reflect.DeepEqual(got, []string{"manual"}) {
		t.Fatalf("other %v", got)
	}
	if proxies[1].Name != "my-name" || proxies[1].Comment != "spaceproxy · истёк 2026-09-28" {
		t.Fatalf("истёкший %+v", proxies[1])
	}
	if len(r.Removed) != 3 || len(r.Updated) != 1 {
		t.Fatalf("отчёт %+v", r)
	}
}

// Лист, в котором не осталось бы ни одного прокси, fairway не примет:
// он остаётся как был вместе со своими прокси.
func TestPlanKeepsLastInList(t *testing.T) {
	cfg := &fairway.Config{
		Proxies: []fairway.Proxy{{ID: "spaceproxy-1", Name: "a"}, {ID: "spaceproxy-2", Name: "b"}},
		Lists: []fairway.List{
			{Name: "only", Proxies: []string{"spaceproxy-1"}},
			{Name: "mixed", Proxies: []string{"spaceproxy-1", "spaceproxy-2"}},
		},
	}
	proxies, lists, r := plan(cfg, []apiProxy{proxy(1, -10), proxy(2, 10)}, nil, defaults(), now)
	if got := ids(proxies); !reflect.DeepEqual(got, []string{"spaceproxy-1", "spaceproxy-2"}) {
		t.Fatalf("прокси %v", got)
	}
	if got := listOf(lists, "only"); !reflect.DeepEqual(got, []string{"spaceproxy-1"}) {
		t.Fatalf("only %v", got)
	}
	if got := listOf(lists, "mixed"); !reflect.DeepEqual(got, []string{"spaceproxy-2"}) {
		t.Fatalf("mixed %v", got)
	}
	if len(r.Kept) != 1 || len(r.Warnings) != 1 {
		t.Fatalf("отчёт %+v", r)
	}
}

// Пустой ответ сервиса ничего не удаляет, а прокси с неразборчивой датой
// остаётся как был.
func TestPlanSafety(t *testing.T) {
	cfg := &fairway.Config{
		Proxies: []fairway.Proxy{{ID: "spaceproxy-1", Name: "a"}, {ID: "spaceproxy-2", Name: "b"}},
		Lists:   []fairway.List{{Name: "l", Proxies: []string{"spaceproxy-1", "spaceproxy-2"}}},
	}
	proxies, lists, _ := plan(cfg, nil, nil, defaults(), now)
	if !reflect.DeepEqual(proxies, cfg.Proxies) || !reflect.DeepEqual(lists, cfg.Lists) {
		t.Fatalf("пустой ответ поменял конфиг: %v %v", proxies, lists)
	}

	bad := proxy(1, 5)
	bad.DateEnd = "someday"
	proxies, _, r := plan(cfg, []apiProxy{bad, proxy(2, 5)}, nil, defaults(), now)
	if got := ids(proxies); !reflect.DeepEqual(got, []string{"spaceproxy-1", "spaceproxy-2"}) {
		t.Fatalf("прокси %v", got)
	}
	if len(r.Warnings) != 1 {
		t.Fatalf("отчёт %+v", r)
	}
}

func TestPlanNameCollision(t *testing.T) {
	cfg := &fairway.Config{Proxies: []fairway.Proxy{{ID: "x", Name: "spaceproxy-1"}}}
	proxies, _, _ := plan(cfg, []apiProxy{proxy(1, 5)}, nil, defaults(), now)
	if proxies[1].Name != "spaceproxy-1-2" {
		t.Fatalf("имя %q", proxies[1].Name)
	}
}

func TestParseSettings(t *testing.T) {
	s, every, err := parseSettings(json.RawMessage(`{"api_key":" k "}`))
	if err != nil || s.APIKey != "k" || every != 10*time.Minute || s.GraceDays != 3 || s.List != "spaceproxy" {
		t.Fatalf("%+v %s %v", s, every, err)
	}
	for _, raw := range []string{`{}`, `{"api_key":"k","scheme":"ftp"}`, `{"api_key":"k","interval":"10s"}`} {
		if _, _, err := parseSettings(json.RawMessage(raw)); err == nil {
			t.Fatalf("%s: нет ошибки", raw)
		}
	}
}
