// Package adopt — прокси сервиса, которые уже есть в fairway под чужим id
// (добавлены руками или раньше синхронизации). Плагин узнаёт свои прокси
// по id «<плагин>-<id в сервисе>»: без этого шага такой прокси появился бы
// второй раз. Здесь ручной прокси с тем же адресом становится прокси
// плагина: получает его id, а ссылки в листах переписываются на этот id.
// Если плагин уже успел добавить свой дубль, ручной убирается, а листы
// ссылаются на прокси плагина.
package adopt

import (
	"slices"
	"strconv"
	"strings"

	fairway "github.com/Crasher69/fairway/plugin-sdk"
)

// Prefixes — id прокси, которыми владеют плагины этого репо. Такие прокси
// принадлежат своему плагину, и чужой плагин их не забирает, даже если
// адрес совпал.
var Prefixes = []string{"spaceproxy-", "proxy6-", "proxys-"}

// Owned — прокси принадлежит какому-то плагину из Prefixes.
func Owned(id string) bool {
	for _, p := range Prefixes {
		if strings.HasPrefix(id, p) {
			return true
		}
	}
	return false
}

// Key — адрес прокси для сравнения: хост без учёта регистра и порт.
func Key(host string, port int) string {
	return strings.ToLower(strings.TrimSpace(host)) + ":" + strconv.Itoa(port)
}

// Result — что сделал Apply.
type Result struct {
	// Adopted — id прокси, ставших прокси плагина: старый id → новый.
	Adopted map[string]string
	// Merged — ручные дубли, убранные в пользу уже существующего прокси
	// плагина: старый id → id плагина.
	Merged map[string]string
}

// Apply переводит ручные прокси на id плагина. target — по адресу (Key)
// id плагина, под которым этот прокси должен жить. Прокси, уже
// принадлежащие плагинам, не трогаются. Возвращает новые каталог и листы;
// у забранного прокси меняется только id, остальное плагин обновит сам.
func Apply(proxies []fairway.Proxy, lists []fairway.List, target map[string]string) ([]fairway.Proxy, []fairway.List, Result) {
	res := Result{Adopted: map[string]string{}, Merged: map[string]string{}}
	exists := make(map[string]bool, len(proxies))
	for _, p := range proxies {
		exists[p.ID] = true
	}
	rename := make(map[string]string)
	out := make([]fairway.Proxy, 0, len(proxies))
	for _, p := range proxies {
		id, ok := target[Key(p.Host, p.Port)]
		if !ok || p.ID == id || p.ID == "" || Owned(p.ID) {
			out = append(out, p)
			continue
		}
		rename[p.ID] = id
		if exists[id] {
			res.Merged[p.ID] = id
			continue
		}
		exists[id] = true
		res.Adopted[p.ID] = id
		p.ID = id
		out = append(out, p)
	}
	if len(rename) == 0 {
		return proxies, lists, res
	}

	newLists := make([]fairway.List, 0, len(lists))
	for _, l := range lists {
		ids := make([]string, 0, len(l.Proxies))
		for _, id := range l.Proxies {
			if to, ok := rename[id]; ok {
				id = to
			}
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
		newLists = append(newLists, fairway.List{Name: l.Name, Proxies: ids})
	}
	return out, newLists, res
}
