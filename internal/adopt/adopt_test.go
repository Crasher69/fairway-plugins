package adopt

import (
	"reflect"
	"testing"

	fairway "github.com/Crasher69/fairway/plugin-sdk"
)

func TestApply(t *testing.T) {
	proxies := []fairway.Proxy{
		{ID: "m1", Name: "руками", Host: "1.1.1.1", Port: 80},
		{ID: "m2", Name: "дубль", Host: "2.2.2.2", Port: 80},
		{ID: "svc-2", Name: "Германия-2", Host: "2.2.2.2", Port: 80},
		{ID: "m3", Name: "чужой", Host: "3.3.3.3", Port: 80},
		{ID: "proxy6-7", Name: "другого плагина", Host: "1.1.1.1", Port: 80},
	}
	lists := []fairway.List{
		{Name: "main", Proxies: []string{"m1", "m2", "m3"}},
		{Name: "svc", Proxies: []string{"svc-2", "m2"}},
	}
	target := map[string]string{Key("1.1.1.1", 80): "svc-1", Key("2.2.2.2", 80): "svc-2"}

	out, outLists, res := Apply(proxies, lists, target)

	var ids []string
	for _, p := range out {
		ids = append(ids, p.ID)
	}
	if !reflect.DeepEqual(ids, []string{"svc-1", "svc-2", "m3", "proxy6-7"}) {
		t.Fatalf("прокси %v", ids)
	}
	if out[0].Name != "руками" {
		t.Fatalf("имя забранного меняет плагин, не Apply: %q", out[0].Name)
	}
	want := []fairway.List{
		{Name: "main", Proxies: []string{"svc-1", "svc-2", "m3"}},
		{Name: "svc", Proxies: []string{"svc-2"}},
	}
	if !reflect.DeepEqual(outLists, want) {
		t.Fatalf("листы %v", outLists)
	}
	if !reflect.DeepEqual(res.Adopted, map[string]string{"m1": "svc-1"}) ||
		!reflect.DeepEqual(res.Merged, map[string]string{"m2": "svc-2"}) {
		t.Fatalf("итог %+v", res)
	}
	if lists[0].Proxies[0] != "m1" || proxies[0].ID != "m1" {
		t.Fatal("вход изменён")
	}
}

func TestApplyNothing(t *testing.T) {
	proxies := []fairway.Proxy{{ID: "m1", Host: "1.1.1.1", Port: 80}}
	lists := []fairway.List{{Name: "main", Proxies: []string{"m1"}}}
	out, outLists, res := Apply(proxies, lists, map[string]string{Key("1.1.1.1", 81): "svc-1"})
	if !reflect.DeepEqual(out, proxies) || !reflect.DeepEqual(outLists, lists) || len(res.Adopted)+len(res.Merged) > 0 {
		t.Fatalf("%v %v %+v", out, outLists, res)
	}
}

func TestKey(t *testing.T) {
	if Key(" Host.Example ", 80) != Key("host.example", 80) {
		t.Fatal("регистр и пробелы")
	}
}
