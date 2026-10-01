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

// Ответ /ip по спецификации proxys.io API v2: список заказов, у каждого
// свои логин, пароль, дата окончания и IP с портами.
const sampleIP = `{"success":true,"data":[
{"order_id":10258,"ip_version":"4","username":"user1","password":"pass1","ip_access":"","expires_at":1493116222,
 "list_ip":[{"ip":"185.22.134.9","port_socks":"1081","port_http":"8081","port_https":"8443"},
            {"ip":"185.22.134.2","port_socks":"1080","port_http":"8080","port_https":"8443"}]},
{"order_id":"10300","ip_version":"6","username":"user2","password":"pass2","expires_at":"2017-05-01 10:00:00","country":"de",
 "list_ip":[{"ip":"2a00:1838::1","port_socks":1090,"port_http":"","port_https":""}]}]}`

func TestParseIP(t *testing.T) {
	data, err := checkEnvelope("ip", []byte(sampleIP))
	if err != nil {
		t.Fatal(err)
	}
	orders, err := parseOrders(data)
	if err != nil {
		t.Fatal(err)
	}
	all := flatten(orders)
	if len(all) != 3 {
		t.Fatalf("прокси %+v", all)
	}
	// IP в заказе — по порядку адресов.
	a := all[0]
	if a.OrderID != 10258 || a.N != 1 || a.IP != "185.22.134.2" || a.PortHTTP != 8080 || a.PortSocks != 1080 ||
		a.User != "user1" || a.Country != "" || !a.End.Equal(time.Unix(1493116222, 0)) {
		t.Fatalf("первый %+v", a)
	}
	if fairwayID(all[1]) != "proxys-10258-2" || all[1].IP != "185.22.134.9" {
		t.Fatalf("второй %+v", all[1])
	}
	c := all[2]
	if c.OrderID != 10300 || c.Country != "DE" || !c.End.Equal(time.Date(2017, 5, 1, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("третий %+v", c)
	}
	// Порта HTTP нет — подключаемся по SOCKS5.
	if got := toProxy(c, "http", stateActive, c.End); got.Scheme != "socks5" || got.Port != 1090 {
		t.Fatalf("socks %+v", got)
	}
}

func TestParseOrdersShapes(t *testing.T) {
	for _, raw := range []string{`[]`, `null`, ``, `{}`} {
		list, err := parseOrders(json.RawMessage(raw))
		if err != nil || len(list) != 0 {
			t.Fatalf("%q: %v %v", raw, list, err)
		}
	}
	list, err := parseOrders(json.RawMessage(`{"order_id":5,"list_ip":[{"ip":"1.2.3.4","port_http":80}]}`))
	if err != nil || len(list) != 1 || list[0].OrderID != 5 {
		t.Fatalf("один заказ: %v %v", list, err)
	}
}

func TestEnvelopeError(t *testing.T) {
	_, err := checkEnvelope("ip", []byte(`{"success":false,"error":{"code":1000,"message":"Указан неправильный ключ"}}`))
	var e *apiError
	if !errors.As(err, &e) || e.Code != 1000 {
		t.Fatalf("ошибка %v", err)
	}
	if err.Error() != "proxys ip: error 1000: Указан неправильный ключ (wrong API key)" {
		t.Fatalf("текст %q", err)
	}
	_, err = checkEnvelope("buy", []byte(`{"success":false,"error":{"code":2000,"message":{"count":["required"]}}}`))
	if !errors.As(err, &e) || e.Code != 2000 || e.Text != `{"count":["required"]}` {
		t.Fatalf("ошибка проверки %v", err)
	}
	_, err = checkEnvelope("ip", []byte(`{"success":false,"error":"oops"}`))
	if !errors.As(err, &e) || e.Text != "oops" {
		t.Fatalf("строка %v", err)
	}
}

// proxy — IP заказа id, который заканчивается через days дней (в прошлом
// — отрицательное).
func proxy(id int64, days float64) apiProxy {
	end := now.Add(time.Duration(days * 24 * float64(time.Hour)))
	return apiProxy{OrderID: id, N: 1, IP: "10.0.0.1", PortHTTP: 8000, PortSocks: 1080, User: "u", Pass: "p",
		Country: "DE", IPVersion: "4", End: end}
}

func defaults() settings { return settings{List: "proxys", Scheme: "http", GraceDays: 3} }

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
	second := proxy(1, 5)
	second.N, second.IP = 2, "10.0.0.2"
	all := []apiProxy{proxy(2, 10), proxy(1, 5), second, proxy(3, -1), proxy(4, -10)}
	proxies, lists, r := plan(cfg, all, defaults(), now)

	if got := ids(proxies); !reflect.DeepEqual(got, []string{"manual", "proxys-1-1", "proxys-1-2", "proxys-2-1"}) {
		t.Fatalf("прокси %v", got)
	}
	if got := listOf(lists, "proxys"); !reflect.DeepEqual(got, []string{"proxys-1-1", "proxys-1-2", "proxys-2-1"}) {
		t.Fatalf("лист %v", got)
	}
	if got := listOf(lists, "main"); !reflect.DeepEqual(got, []string{"manual"}) {
		t.Fatalf("чужой лист %v", got)
	}
	p := proxies[1]
	want := fairway.Proxy{ID: "proxys-1-1", Name: "Германия-1-1", Scheme: "http", Host: "10.0.0.1", Port: 8000,
		Login: "u", Password: "p", Country: "DE", Comment: "proxys · до 2026-10-05"}
	if p != want {
		t.Fatalf("прокси\n%+v\nwant\n%+v", p, want)
	}
	if len(r.Added) != 3 || len(r.Removed) != 0 {
		t.Fatalf("отчёт %+v", r)
	}
}

func TestPlanSchemeAndNoList(t *testing.T) {
	s := defaults()
	s.Scheme, s.List = "socks5", ""
	proxies, lists, _ := plan(&fairway.Config{}, []apiProxy{proxy(1, 5)}, s, now)
	if p := proxies[0]; p.Scheme != "socks5" || p.Port != 1080 {
		t.Fatalf("socks5 %+v", p)
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
			{ID: "proxys-1-1", Name: "my-name", Comment: "x"},
			{ID: "proxys-2-1", Name: "b"},
			{ID: "proxys-4-1", Name: "d", Comment: "свой"},
		},
		Lists: []fairway.List{
			{Name: "main", Proxies: []string{"manual", "proxys-1-1", "proxys-2-1", "proxys-4-1"}},
			{Name: "other", Proxies: []string{"proxys-2-1", "manual"}},
		},
	}
	// proxys-4-1 сервис не вернул вовсе, даты в комментарии нет.
	proxies, lists, r := plan(cfg, []apiProxy{proxy(1, -2), proxy(2, -4)}, defaults(), now)

	if got := ids(proxies); !reflect.DeepEqual(got, []string{"manual", "proxys-1-1"}) {
		t.Fatalf("прокси %v", got)
	}
	if got := listOf(lists, "main"); !reflect.DeepEqual(got, []string{"manual", "proxys-1-1"}) {
		t.Fatalf("main %v", got)
	}
	if got := listOf(lists, "other"); !reflect.DeepEqual(got, []string{"manual"}) {
		t.Fatalf("other %v", got)
	}
	if proxies[1].Name != "my-name" || proxies[1].Comment != "proxys · истёк 2026-09-28" {
		t.Fatalf("истёкший %+v", proxies[1])
	}
	if len(r.Removed) != 2 || len(r.Updated) != 1 {
		t.Fatalf("отчёт %+v", r)
	}
}

// /ip может не отдавать истёкшие заказы: пропавший прокси держится, пока
// по дате в комментарии не пройдут grace_days.
func TestPlanMissingKeptByComment(t *testing.T) {
	cfg := &fairway.Config{
		Proxies: []fairway.Proxy{
			{ID: "proxys-5-1", Name: "a", Comment: "proxys · до 2026-09-28"},
			{ID: "proxys-6-1", Name: "b", Comment: "proxys · истёк 2026-09-26"},
			{ID: "proxys-7-1", Name: "c", Comment: "proxys · до 2026-10-20"},
		},
		Lists: []fairway.List{{Name: "l", Proxies: []string{"proxys-5-1", "proxys-6-1", "proxys-7-1", "proxys-9-1"}}},
	}
	proxies, lists, r := plan(cfg, []apiProxy{proxy(9, 10)}, defaults(), now)
	if got := ids(proxies); !reflect.DeepEqual(got, []string{"proxys-5-1", "proxys-7-1", "proxys-9-1"}) {
		t.Fatalf("прокси %v", got)
	}
	if got := listOf(lists, "l"); !reflect.DeepEqual(got, []string{"proxys-5-1", "proxys-7-1", "proxys-9-1"}) {
		t.Fatalf("лист %v", got)
	}
	if !reflect.DeepEqual(r.Removed, []string{"proxys-6-1"}) {
		t.Fatalf("отчёт %+v", r)
	}
}

func TestInGrace(t *testing.T) {
	// Дата — день окончания, считаем до его конца; сейчас 30-е 12:00.
	for comment, want := range map[string]bool{
		"proxys · до 2026-09-27":    true,  // 28-е 00:00 + 3 дня — ещё нет
		"proxys · до 2026-09-26":    false, // 27-е 00:00 + 3 дня — уже прошло
		"proxys · истёк 2026-09-25": false,
		"proxys · до когда-то":      false,
		"руками":                    false,
	} {
		if got := inGrace(fairway.Proxy{Comment: comment}, now, 3); got != want {
			t.Fatalf("%q: %v", comment, got)
		}
	}
}

// Лист, в котором не осталось бы ни одного прокси, fairway не примет:
// он остаётся как был вместе со своими прокси.
func TestPlanKeepsLastInList(t *testing.T) {
	cfg := &fairway.Config{
		Proxies: []fairway.Proxy{{ID: "proxys-1-1", Name: "a"}, {ID: "proxys-2-1", Name: "b"}},
		Lists: []fairway.List{
			{Name: "only", Proxies: []string{"proxys-1-1"}},
			{Name: "mixed", Proxies: []string{"proxys-1-1", "proxys-2-1"}},
		},
	}
	proxies, lists, r := plan(cfg, []apiProxy{proxy(1, -10), proxy(2, 10)}, defaults(), now)
	if got := ids(proxies); !reflect.DeepEqual(got, []string{"proxys-1-1", "proxys-2-1"}) {
		t.Fatalf("прокси %v", got)
	}
	if got := listOf(lists, "only"); !reflect.DeepEqual(got, []string{"proxys-1-1"}) {
		t.Fatalf("only %v", got)
	}
	if got := listOf(lists, "mixed"); !reflect.DeepEqual(got, []string{"proxys-2-1"}) {
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
		Proxies: []fairway.Proxy{{ID: "proxys-1-1", Name: "a"}, {ID: "proxys-2-1", Name: "b"}},
		Lists:   []fairway.List{{Name: "l", Proxies: []string{"proxys-1-1", "proxys-2-1"}}},
	}
	proxies, lists, _ := plan(cfg, nil, defaults(), now)
	if !reflect.DeepEqual(proxies, cfg.Proxies) || !reflect.DeepEqual(lists, cfg.Lists) {
		t.Fatalf("пустой ответ поменял конфиг: %v %v", proxies, lists)
	}

	bad := proxy(1, 5)
	bad.End = time.Time{}
	proxies, _, r := plan(cfg, []apiProxy{bad, proxy(2, 5)}, defaults(), now)
	if got := ids(proxies); !reflect.DeepEqual(got, []string{"proxys-1-1", "proxys-2-1"}) {
		t.Fatalf("прокси %v", got)
	}
	if len(r.Warnings) != 1 {
		t.Fatalf("отчёт %+v", r)
	}
}

func TestPlanNameCollision(t *testing.T) {
	cfg := &fairway.Config{Proxies: []fairway.Proxy{{ID: "x", Name: "Германия-1-1"}}}
	proxies, _, _ := plan(cfg, []apiProxy{proxy(1, 5)}, defaults(), now)
	if proxies[1].Name != "Германия-1-1-2" {
		t.Fatalf("имя %q", proxies[1].Name)
	}
	noCountry := proxy(2, 5)
	noCountry.Country = ""
	proxies, _, _ = plan(&fairway.Config{}, []apiProxy{noCountry}, defaults(), now)
	if proxies[0].Name != "proxys-2-1" {
		t.Fatalf("без страны %q", proxies[0].Name)
	}
}

func TestParseSettings(t *testing.T) {
	s, every, err := parseSettings(json.RawMessage(`{"api_key":" k "}`))
	if err != nil || s.APIKey != "k" || every != 10*time.Minute || s.GraceDays != 3 || s.List != "proxys" || s.Scheme != "http" {
		t.Fatalf("%+v %s %v", s, every, err)
	}
	for _, raw := range []string{`{}`, `{"api_key":"k","scheme":"ftp"}`, `{"api_key":"k","interval":"10s"}`, `{"api_key":"a&b"}`} {
		if _, _, err := parseSettings(json.RawMessage(raw)); err == nil {
			t.Fatalf("%s: нет ошибки", raw)
		}
	}
}

func TestRedact(t *testing.T) {
	got := redact(`Get "https://proxys.world/api/v2/ip?key=sec+ret": timeout; sec ret`, "sec ret")
	if got != `Get "https://proxys.world/api/v2/ip?key=***": timeout; ***` {
		t.Fatalf("%q", got)
	}
}

// Руками добавленный прокси узнаётся по любому из двух портов IP.
func TestPlanAdoptsManualProxy(t *testing.T) {
	p1, p2 := proxy(1, 5), proxy(2, 5)
	p1.IP, p2.IP = "10.0.0.1", "10.0.0.2"
	own2 := toProxy(p2, "http", stateActive, now.AddDate(0, 0, 5))
	own2.Name = "Германия-2-1"
	cfg := &fairway.Config{
		Proxies: []fairway.Proxy{
			{ID: "m1", Name: "руками", Scheme: "socks5", Host: "10.0.0.1", Port: 1080, Comment: "мой"},
			{ID: "m2", Name: "дубль", Host: "10.0.0.2", Port: 8000},
			own2,
		},
		Lists: []fairway.List{
			{Name: "main", Proxies: []string{"m1", "m2"}},
			{Name: "proxys", Proxies: []string{"proxys-2-1"}},
		},
	}
	proxies, lists, r := plan(cfg, []apiProxy{p1, p2}, defaults(), now)

	if got := ids(proxies); !reflect.DeepEqual(got, []string{"proxys-1-1", "proxys-2-1"}) {
		t.Fatalf("прокси %v", got)
	}
	if a := proxies[0]; a.Name != "Германия-1-1" || a.Comment != "proxys · до 2026-10-05" || a.Port != 8000 {
		t.Fatalf("забранный %+v", a)
	}
	if got := listOf(lists, "main"); !reflect.DeepEqual(got, []string{"proxys-1-1", "proxys-2-1"}) {
		t.Fatalf("main %v", got)
	}
	if !reflect.DeepEqual(r.Adopted, []string{"m1 → proxys-1-1"}) || !reflect.DeepEqual(r.Merged, []string{"m2 → proxys-2-1"}) ||
		len(r.Added) > 0 || len(r.Updated) > 0 {
		t.Fatalf("отчёт %+v", r)
	}

	cfg = &fairway.Config{Proxies: proxies, Lists: lists}
	if _, _, r = plan(cfg, []apiProxy{p1, p2}, defaults(), now); r.changed() {
		t.Fatalf("повтор %+v", r)
	}
}
