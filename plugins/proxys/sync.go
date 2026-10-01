package main

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	fairway "github.com/Crasher69/fairway/plugin-sdk"

	"github.com/Crasher69/fairway-plugins/internal/adopt"
	"github.com/Crasher69/fairway-plugins/internal/countries"
)

// idPrefix — id прокси в fairway = idPrefix + «<заказ>-<номер IP>». По
// нему плагин узнаёт свои прокси: имя и комментарий можно менять в
// панели, id — нет, и на него ссылаются листы. Чужие прокси плагин не
// трогает.
const idPrefix = "proxys-"

// serviceID — прокси в сервисе: «<заказ>-<номер IP в заказе>».
func serviceID(p apiProxy) string { return fmt.Sprintf("%d-%d", p.OrderID, p.N) }

func fairwayID(p apiProxy) string { return idPrefix + serviceID(p) }

// state — во что превращается прокси сервиса по правилам синхронизации.
type state int

const (
	// stateActive — работает: есть в каталоге, новый попадает в лист.
	stateActive state = iota
	// stateGrace — истёк недавно: не трогаем, только комментарий.
	stateGrace
	// stateGone — истёк давно или удалён: убираем из листов и каталога.
	stateGone
)

func classify(p apiProxy, now time.Time, graceDays int) (state, time.Time, error) {
	end, err := p.end()
	if err != nil {
		return stateGone, end, err
	}
	if p.IP == "" || p.port("http") == 0 {
		return stateGone, end, fmt.Errorf("proxy %s: no address or port", serviceID(p))
	}
	switch {
	case end.After(now):
		return stateActive, end, nil
	case now.Sub(end) <= time.Duration(graceDays)*24*time.Hour:
		return stateGrace, end, nil
	default:
		return stateGone, end, nil
	}
}

// report — что поменяла синхронизация, для лога и страницы.
type report struct {
	Added   []string `json:"added"`
	Updated []string `json:"updated"`
	Removed []string `json:"removed"`
	// Adopted — прокси, которые уже были в fairway с тем же адресом и
	// стали прокси плагина («старый id → новый»).
	Adopted []string `json:"adopted"`
	// Merged — дубли прокси плагина с тем же адресом, убранные из каталога
	// («старый id → id плагина»); листы теперь ссылаются на прокси плагина.
	Merged []string `json:"merged"`
	// Kept — прокси, которые надо было убрать, но они последние в листе:
	// пустой лист fairway не примет.
	Kept     []string `json:"kept"`
	Warnings []string `json:"warnings"`
}

// changed — синхронизации есть что записать в конфиг.
func (r report) changed() bool {
	return len(r.Added)+len(r.Updated)+len(r.Removed)+len(r.Adopted)+len(r.Merged) > 0
}

func (r report) String() string {
	s := fmt.Sprintf("added %d, updated %d, removed %d", len(r.Added), len(r.Updated), len(r.Removed))
	if len(r.Adopted) > 0 {
		s += fmt.Sprintf(", adopted %d", len(r.Adopted))
	}
	if len(r.Merged) > 0 {
		s += fmt.Sprintf(", merged %d duplicates", len(r.Merged))
	}
	if len(r.Kept) > 0 {
		s += fmt.Sprintf(", kept %d (last in a list)", len(r.Kept))
	}
	return s
}

// plan приводит прокси и листы fairway к списку сервиса. all — все прокси
// аккаунта (IP всех заказов из /ip): свой прокси, которого там нет, удалён.
// Но /ip может не отдавать истёкшие заказы, поэтому пропавший прокси с
// датой окончания в комментарии («до 2026-10-05») держится, пока не
// пройдут grace_days.
// Возвращает новые разделы proxies и lists; прокси без префикса idPrefix
// остаются как были.
func plan(cfg *fairway.Config, all []apiProxy, s settings, now time.Time) ([]fairway.Proxy, []fairway.List, report) {
	var r report

	type target struct {
		proxy fairway.Proxy
		state state
	}
	want := make(map[string]target, len(all))
	// unparsed — прокси, чью дату окончания не разобрать: их не трогаем.
	unparsed := make(map[string]bool)
	for _, p := range all {
		st, end, err := classify(p, now, s.GraceDays)
		if err != nil {
			r.Warnings = append(r.Warnings, err.Error())
			unparsed[fairwayID(p)] = true
			continue
		}
		want[fairwayID(p)] = target{proxy: toProxy(p, s.Scheme, st, end), state: st}
	}
	// Прокси сервиса, которые уже есть в fairway под другим id (добавлены
	// руками), становятся своими: id плагина, ссылки в листах — на него.
	// Иначе тот же прокси появился бы второй раз.
	byAddress := make(map[string]string)
	ambiguous := make(map[string]bool)
	for _, p := range all {
		id := fairwayID(p)
		if t, ok := want[id]; !ok || t.state == stateGone {
			continue
		}
		for _, key := range addressKeys(p) {
			if other, ok := byAddress[key]; ok && other != id {
				ambiguous[key] = true
			}
			byAddress[key] = id
		}
	}
	for key := range ambiguous {
		delete(byAddress, key)
	}
	catalog, catalogLists, ad := adopt.Apply(cfg.Proxies, cfg.Lists, byAddress)
	cfg = &fairway.Config{Proxies: catalog, Lists: catalogLists}
	adopted := make(map[string]bool, len(ad.Adopted))
	for from, to := range ad.Adopted {
		adopted[to] = true
		r.Adopted = append(r.Adopted, from+" → "+to)
	}
	for from, to := range ad.Merged {
		r.Merged = append(r.Merged, from+" → "+to)
	}
	sort.Strings(r.Adopted)
	sort.Strings(r.Merged)

	gone := make(map[string]bool)
	for id, t := range want {
		if t.state == stateGone {
			gone[id] = true
		}
	}
	// Своего прокси нет в ответе — сервис его больше не знает. Но пустой
	// ответ скорее значит чужой ключ или сбой, чем пустой аккаунт: тогда
	// ничего не удаляем.
	if len(all) > 0 {
		for _, p := range cfg.Proxies {
			if _, ok := want[p.ID]; !ok && !unparsed[p.ID] && strings.HasPrefix(p.ID, idPrefix) && !inGrace(p, now, s.GraceDays) {
				gone[p.ID] = true
			}
		}
	}

	// Листы: убираем ушедшие прокси, но лист, в котором не осталось бы
	// ничего, оставляем как есть — его прокси остаются и в каталоге.
	kept := make(map[string]bool)
	lists := make([]fairway.List, 0, len(cfg.Lists)+1)
	for _, l := range cfg.Lists {
		rest := slices.DeleteFunc(slices.Clone(l.Proxies), func(id string) bool { return gone[id] })
		if len(rest) == 0 && len(l.Proxies) > 0 {
			for _, id := range l.Proxies {
				kept[id] = true
			}
			r.Warnings = append(r.Warnings, fmt.Sprintf("list %q would be empty, left as is", l.Name))
			rest = l.Proxies
		}
		lists = append(lists, fairway.List{Name: l.Name, Proxies: rest})
	}

	// Каталог: свои прокси обновляем или убираем, чужие не трогаем.
	have := make(map[string]bool, len(cfg.Proxies))
	names := make(map[string]bool, len(cfg.Proxies))
	for _, p := range cfg.Proxies {
		names[p.Name] = true
	}
	proxies := make([]fairway.Proxy, 0, len(cfg.Proxies)+len(want))
	for _, p := range cfg.Proxies {
		have[p.ID] = true
		if !strings.HasPrefix(p.ID, idPrefix) {
			proxies = append(proxies, p)
			continue
		}
		if gone[p.ID] {
			if kept[p.ID] {
				r.Kept = append(r.Kept, p.ID)
				proxies = append(proxies, p)
			} else {
				r.Removed = append(r.Removed, p.ID)
			}
			continue
		}
		t, ok := want[p.ID]
		if !ok {
			// Сервис не ответил ничем — оставляем как есть.
			proxies = append(proxies, p)
			continue
		}
		updated := t.proxy
		updated.Name = p.Name // имя — дело человека
		if adopted[p.ID] {
			// Забранный прокси получает имя плагина.
			delete(names, p.Name)
			updated.Name = uniqueName(defaultName(t.proxy), names)
			names[updated.Name] = true
		}
		if updated != p && !adopted[p.ID] {
			r.Updated = append(r.Updated, p.ID)
		}
		proxies = append(proxies, updated)
	}

	// Новые — только активные, по порядку id.
	var added []string
	for id, t := range want {
		if t.state == stateActive && !have[id] {
			added = append(added, id)
		}
	}
	sort.Slice(added, func(i, j int) bool { return idLess(added[i], added[j]) })
	for _, id := range added {
		p := want[id].proxy
		p.Name = uniqueName(defaultName(p), names)
		names[p.Name] = true
		proxies = append(proxies, p)
	}
	r.Added = added

	if s.List != "" && len(added) > 0 {
		i := slices.IndexFunc(lists, func(l fairway.List) bool { return l.Name == s.List })
		if i < 0 {
			lists = append(lists, fairway.List{Name: s.List})
			i = len(lists) - 1
		}
		lists[i].Proxies = append(slices.Clone(lists[i].Proxies), added...)
	}
	return proxies, lists, r
}

func toProxy(p apiProxy, scheme string, st state, end time.Time) fairway.Proxy {
	comment := commentPrefix + "до " + end.Format(dateLayout)
	if st != stateActive {
		comment = commentPrefix + "истёк " + end.Format(dateLayout)
	}
	sc := p.scheme(scheme)
	return fairway.Proxy{
		ID:       fairwayID(p),
		Scheme:   sc,
		Host:     p.IP,
		Port:     p.port(sc),
		Login:    p.User,
		Password: p.Pass,
		Country:  strings.ToUpper(p.Country),
		Comment:  comment,
	}
}

// defaultName — имя нового прокси: страна, заказ и номер IP,
// «Россия-1234-1».
// Без страны — id в fairway.
func defaultName(p fairway.Proxy) string {
	country := countries.Name(p.Country)
	if country == "" {
		return p.ID
	}
	return country + "-" + strings.TrimPrefix(p.ID, idPrefix)
}

// uniqueName — base, а если такое имя уже занято — с номером.
func uniqueName(base string, taken map[string]bool) string {
	name := base
	for n := 2; taken[name]; n++ {
		name = fmt.Sprintf("%s-%d", base, n)
	}
	return name
}

func idLess(a, b string) bool {
	x, y := idParts(a), idParts(b)
	if x[0] != y[0] {
		return x[0] < y[0]
	}
	return x[1] < y[1]
}

func idParts(id string) [2]int64 {
	order, n, _ := strings.Cut(strings.TrimPrefix(id, idPrefix), "-")
	a, _ := strconv.ParseInt(order, 10, 64)
	b, _ := strconv.ParseInt(n, 10, 64)
	return [2]int64{a, b}
}

// addressKeys — адреса прокси сервиса, по которым его можно узнать в
// fairway (adopt.Key).
// У IP два порта, руками могли добавить любой.
func addressKeys(p apiProxy) []string {
	var keys []string
	for _, port := range []int{p.PortHTTP, p.PortSocks} {
		if port > 0 {
			keys = append(keys, adopt.Key(p.IP, port))
		}
	}
	return keys
}

// scheme — протокол из настроек; если у IP нет порта для него — другой.
func (p apiProxy) scheme(want string) string {
	if want == "socks5" && p.PortSocks == 0 && p.PortHTTP > 0 {
		return "http"
	}
	if want == "http" && p.PortHTTP == 0 && p.PortSocks > 0 {
		return "socks5"
	}
	return want
}

// port — порт IP для протокола (если его нет — порт другого протокола).
func (p apiProxy) port(scheme string) int {
	if p.scheme(scheme) == "socks5" {
		return p.PortSocks
	}
	return p.PortHTTP
}

const (
	commentPrefix = "proxys · "
	dateLayout    = "2006-01-02"
)

// inGrace — свой прокси, которого нет в ответе, но по дате в комментарии
// он истёк не больше grace_days дней назад (или ещё не истёк): истёкшие
// заказы могут пропадать из /ip сразу, а убирать их раньше срока нельзя.
// Без даты в комментарии (его поменяли руками) — не держим.
func inGrace(p fairway.Proxy, now time.Time, graceDays int) bool {
	rest, ok := strings.CutPrefix(p.Comment, commentPrefix)
	if !ok {
		return false
	}
	_, date, ok := strings.Cut(rest, " ")
	if !ok {
		return false
	}
	end, err := time.Parse(dateLayout, date)
	if err != nil {
		return false
	}
	// В комментарии только день: считаем, что заказ кончился в конце дня.
	end = end.Add(24 * time.Hour)
	return now.Sub(end) <= time.Duration(graceDays)*24*time.Hour
}
