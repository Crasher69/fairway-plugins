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

// idPrefix — id прокси в fairway = idPrefix + id в spaceproxy. По нему
// плагин узнаёт свои прокси: имя и комментарий можно менять в панели, id —
// нет, и на него ссылаются листы. Чужие прокси плагин не трогает.
const idPrefix = "spaceproxy-"

func fairwayID(id int64) string { return idPrefix + strconv.FormatInt(id, 10) }

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
	end, err := parseTime(p.DateEnd)
	if err != nil {
		return stateGone, end, fmt.Errorf("proxy %d: date_end: %w", p.ID, err)
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

// plan приводит прокси и листы fairway к списку сервиса. live — всё, что не
// удалено (status=exclude_deleted), deleted — удалённые (status=deleted).
// Возвращает новые разделы proxies и lists; прокси без префикса idPrefix
// остаются как были.
func plan(cfg *fairway.Config, live, deleted []apiProxy, s settings, now time.Time) ([]fairway.Proxy, []fairway.List, report) {
	var r report

	type target struct {
		proxy fairway.Proxy
		state state
	}
	want := make(map[string]target, len(live))
	// unparsed — прокси, чью дату окончания не разобрать: их не трогаем.
	unparsed := make(map[string]bool)
	for _, p := range live {
		st, end, err := classify(p, now, s.GraceDays)
		if err != nil {
			r.Warnings = append(r.Warnings, err.Error())
			unparsed[fairwayID(p.ID)] = true
			continue
		}
		want[fairwayID(p.ID)] = target{proxy: toProxy(p, s.Scheme, st, end), state: st}
	}
	// Прокси сервиса, которые уже есть в fairway под другим id (добавлены
	// руками), становятся своими: id плагина, ссылки в листах — на него.
	// Иначе тот же прокси появился бы второй раз.
	byAddress := make(map[string]string)
	ambiguous := make(map[string]bool)
	for _, p := range live {
		id := fairwayID(p.ID)
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
	for _, p := range deleted {
		id := fairwayID(p.ID)
		if _, ok := want[id]; !ok {
			gone[id] = true
		}
	}
	for id, t := range want {
		if t.state == stateGone {
			gone[id] = true
		}
	}
	// Своего прокси нет ни среди живых, ни среди удалённых — сервис его
	// больше не знает. Но пустой ответ скорее значит чужой ключ или сбой,
	// чем пустой аккаунт: тогда ничего не удаляем.
	if len(live) > 0 || len(deleted) > 0 {
		for _, p := range cfg.Proxies {
			if _, ok := want[p.ID]; !ok && !unparsed[p.ID] && strings.HasPrefix(p.ID, idPrefix) {
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
		if p.Name == p.ID || adopted[p.ID] {
			// Старое имя по умолчанию (spaceproxy-<id>) и имя забранного
			// прокси меняем на имя плагина.
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
	port := p.PortHTTP
	if scheme == "socks5" {
		port = p.PortSocks5
	}
	comment := "spaceproxy · до " + end.Format("2006-01-02")
	if st != stateActive {
		comment = "spaceproxy · истёк " + end.Format("2006-01-02")
	}
	return fairway.Proxy{
		ID:       fairwayID(p.ID),
		Scheme:   scheme,
		Host:     p.IP,
		Port:     port,
		Login:    p.Username,
		Password: p.Password,
		Country:  strings.ToUpper(p.Country),
		Comment:  comment,
	}
}

// defaultName — имя нового прокси: страна и id в сервисе, «США-369160».
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
	x, _ := strconv.ParseInt(strings.TrimPrefix(a, idPrefix), 10, 64)
	y, _ := strconv.ParseInt(strings.TrimPrefix(b, idPrefix), 10, 64)
	return x < y
}

// addressKeys — адреса прокси сервиса, по которым его можно узнать в
// fairway (adopt.Key).
func addressKeys(p apiProxy) []string {
	return []string{adopt.Key(p.IP, p.PortHTTP), adopt.Key(p.IP, p.PortSocks5)}
}
