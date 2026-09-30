#!/bin/sh
# Сборка плагинов: каждый plugins/<имя> собирается в dist/<имя>/ (готовая
# папка для <data>/plugins/) и в архив dist/<имя>-<версия>.zip.
#
#   ./build.sh            # все плагины
#   ./build.sh hello      # только перечисленные
#
# Нужны Go 1.24+, jq и zip.
set -eu
cd "$(dirname "$0")"

if [ $# -eq 0 ]; then
	set -- $(ls plugins)
fi

mkdir -p dist
for name in "$@"; do
	src="plugins/$name"
	[ -f "$src/manifest.json" ] || { echo "$src/manifest.json: not found" >&2; exit 1; }

	# Те же требования, что проверяет fairway при загрузке: имя из манифеста
	# совпадает с каталогом, версия задана.
	mname=$(jq -r '.name // ""' "$src/manifest.json")
	version=$(jq -r '.version // ""' "$src/manifest.json")
	[ "$mname" = "$name" ] || { echo "$src: manifest name \"$mname\" does not match directory" >&2; exit 1; }
	[ -n "$version" ] || { echo "$src: manifest has no version" >&2; exit 1; }

	out="dist/$name"
	rm -rf "$out" "dist/$name-$version.zip"
	mkdir -p "$out"
	GOOS=wasip1 GOARCH=wasm go build -trimpath -buildmode=c-shared -o "$out/plugin.wasm" "./$src"
	cp "$src/manifest.json" "$out/"
	if [ -d "$src/ui" ]; then
		cp -R "$src/ui" "$out/"
	fi
	(cd dist && zip -qr "$name-$version.zip" "$name")
	echo "dist/$name-$version.zip"
done
