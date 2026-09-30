// hello — минимальный плагин fairway: здоровается, раз в интервал пишет
// в лог, сколько прокси в конфиге, и показывает то же на своей странице в
// панели (ui/index.html). Перенесён из plugin-sdk/examples/hello репозитория
// fairway.
//
// Сборка: ./build.sh hello (из корня репозитория). Установка — см. README.
package main

import (
	"encoding/json"
	"fmt"
	"time"

	fairway "github.com/Crasher69/fairway/plugin-sdk"
)

type settings struct {
	Interval string `json:"interval"`
}

func init() {
	fairway.Register(fairway.Plugin{
		Init: func(raw json.RawMessage) error {
			s := settings{Interval: "10m"}
			if len(raw) > 0 {
				if err := json.Unmarshal(raw, &s); err != nil {
					return err
				}
			}
			every, err := time.ParseDuration(s.Interval)
			if err != nil {
				return err
			}
			fairway.Logf("hello, reporting every %s", every)
			return fairway.Every(every)
		},
		Tick: func() error {
			c, err := count()
			if err != nil {
				return err
			}
			fairway.Logf("proxies: %d, lists: %d", c.Proxies, c.Lists)
			return nil
		},
		// Вызовы со страницы плагина: window.fairway.call("counts").
		Call: func(method string, params json.RawMessage) (any, error) {
			if method != "counts" {
				return nil, fmt.Errorf("unknown method %q", method)
			}
			return count()
		},
	})
}

type counts struct {
	Proxies int `json:"proxies"`
	Lists   int `json:"lists"`
	Domains int `json:"domains"`
}

func count() (counts, error) {
	cfg, err := fairway.GetConfig()
	if err != nil {
		return counts{}, err
	}
	return counts{Proxies: len(cfg.Proxies), Lists: len(cfg.Lists), Domains: len(cfg.Domains)}, nil
}

// main в режиме reactor не вызывается, но пакет main без него не собрать.
func main() {}
