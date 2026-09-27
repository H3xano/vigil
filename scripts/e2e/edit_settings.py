#!/usr/bin/env python3
"""Edits vigil's settings JSON inside its SharedPreferences XML file."""
import html, json, re, sys

path, patch = sys.argv[1], json.loads(sys.argv[2])
xml = open(path).read()
m = re.search(r'<string name="settings_v1">(.*?)</string>', xml, re.S)
settings = json.loads(html.unescape(m.group(1))) if m else {}
def merge(a, b):
    for k, v in b.items():
        a[k] = merge(a.get(k, {}), v) if isinstance(v, dict) else v
    return a
settings = merge(settings, patch)
body = '<string name="settings_v1">%s</string>' % html.escape(json.dumps(settings), quote=True)
xml = xml.replace(m.group(0), body) if m else xml.replace("</map>", body + "\n</map>")
open(path, "w").write(xml)
