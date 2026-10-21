#!/usr/bin/env python3
"""Сборка: проверка каталога по схеме и выпуск наборов правил + контрольных сумм.

Запуск: python3 scripts/build.py <каталог-вывода>
Выпуск на каждый список:
  <kind>.json            - сам каталог (как есть);
  <kind>.rules.json      - набор правил: domain_suffix + ip_cidr (читается как rule-set source);
  <kind>.<платформа>.rules.json - набор по именам программ платформы;
  у каждого файла рядом .sha256sum.
"""
import hashlib, json, sys
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parent.parent
PLATFORM_FIELD = {"windows": "process_name", "linux": "process_name",
                  "macos": "process_name", "android": "package_name"}


def uniq(values):
    return sorted(set(values))


def write(out: Path, name: str, text: str) -> None:
    (out / name).write_text(text, encoding="utf-8", newline="\n")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    (out / (name + ".sha256sum")).write_text(f"{digest}  {name}\n", encoding="utf-8", newline="\n")


def dump(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=False) + "\n"


def main(out_dir: str) -> int:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    schema = json.loads((ROOT / "schema.json").read_text(encoding="utf-8"))
    for src in sorted((ROOT / "catalog").glob("*.json")):
        text = src.read_text(encoding="utf-8")
        doc = json.loads(text)
        jsonschema.validate(doc, schema)
        kind = doc["kind"]
        if src.stem != kind:
            raise SystemExit(f"{src.name}: имя файла не совпадает с kind={kind}")
        entries = doc["entries"]
        domains = uniq(d for e in entries for d in e.get("domains", []))
        cidrs = uniq(c for e in entries for c in e.get("ip_cidr", []))
        rule = {}
        if domains:
            rule["domain_suffix"] = domains
        if cidrs:
            rule["ip_cidr"] = cidrs
        write(out, f"{kind}.json", text)
        write(out, f"{kind}.rules.json", dump({"version": 2, "rules": [rule] if rule else []}))
        for platform, field in PLATFORM_FIELD.items():
            names = uniq(a for e in entries for a in e.get("apps", {}).get(platform, []))
            body = {"version": 2, "rules": [{field: names}] if names else []}
            write(out, f"{kind}.{platform}.rules.json", dump(body))
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    sys.exit(main(sys.argv[1]))
