#!/usr/bin/env python3
"""Render the launcher icon to a 512x512 PNG for the F-Droid metadata.

Reads the adaptive icon (background colour + foreground vector drawable) from
the app resources and rasterises it with Pillow, so the store icon always
matches the launcher icon. Supports the path commands the drawable uses
(M/L/H/V/C/S/Q/A/Z, absolute and relative) and evenOdd/nonZero fill types
(nonZero is treated as evenOdd, which is equivalent for these shapes).

Usage: python3 packaging/fdroid/render_icon.py
"""
import math
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw

ROOT = Path(__file__).resolve().parents[2]
RES = ROOT / "android/app/src/main/res"
OUT = ROOT / "fastlane/metadata/android/en-US/images/icon.png"
A = "{http://schemas.android.com/apk/res/android}"
SIZE = 512
SS = 4  # supersampling factor
# Launchers show the central 72x72 of the 108x108 adaptive-icon canvas.
VISIBLE = (18.0, 18.0, 72.0)


def colour(value):
    value = value.lstrip("#")
    if len(value) == 8:
        a, value = int(value[:2], 16), value[2:]
    else:
        a = 255
    return tuple(int(value[i:i + 2], 16) for i in (0, 2, 4)) + (a,)


def background_colour():
    name = re.search(r"@color/(\w+)", (RES / "mipmap-anydpi-v26/ic_launcher.xml").read_text()).group(1)
    for c in ET.parse(RES / "values/colors.xml").getroot():
        if c.get("name") == name:
            return colour(c.text.strip())
    raise SystemExit(f"colour {name} not found")


def tokens(d):
    for m in re.finditer(r"[A-Za-z]|-?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?", d):
        yield m.group(0)


def arc(p0, rx, ry, phi, large, sweep, p1, steps=64):
    """SVG endpoint arc to points (SVG spec, appendix F.6)."""
    if rx == 0 or ry == 0:
        return [p1]
    phi = math.radians(phi)
    cos, sin = math.cos(phi), math.sin(phi)
    dx, dy = (p0[0] - p1[0]) / 2, (p0[1] - p1[1]) / 2
    x1, y1 = cos * dx + sin * dy, -sin * dx + cos * dy
    rx, ry = abs(rx), abs(ry)
    lam = x1 ** 2 / rx ** 2 + y1 ** 2 / ry ** 2
    if lam > 1:
        rx, ry = rx * math.sqrt(lam), ry * math.sqrt(lam)
    num = rx ** 2 * ry ** 2 - rx ** 2 * y1 ** 2 - ry ** 2 * x1 ** 2
    den = rx ** 2 * y1 ** 2 + ry ** 2 * x1 ** 2
    coef = math.sqrt(max(0.0, num / den)) * (-1 if large == sweep else 1)
    cx1, cy1 = coef * rx * y1 / ry, -coef * ry * x1 / rx
    cx = cos * cx1 - sin * cy1 + (p0[0] + p1[0]) / 2
    cy = sin * cx1 + cos * cy1 + (p0[1] + p1[1]) / 2

    def angle(ux, uy, vx, vy):
        a = math.atan2(ux * vy - uy * vx, ux * vx + uy * vy)
        return a

    t1 = angle(1, 0, (x1 - cx1) / rx, (y1 - cy1) / ry)
    dt = angle((x1 - cx1) / rx, (y1 - cy1) / ry, (-x1 - cx1) / rx, (-y1 - cy1) / ry)
    if not sweep and dt > 0:
        dt -= 2 * math.pi
    elif sweep and dt < 0:
        dt += 2 * math.pi
    pts = []
    for i in range(1, steps + 1):
        t = t1 + dt * i / steps
        x, y = rx * math.cos(t), ry * math.sin(t)
        pts.append((cos * x - sin * y + cx, sin * x + cos * y + cy))
    return pts


def bezier(pts, steps=48):
    out = []
    for i in range(1, steps + 1):
        t = i / steps
        work = list(pts)
        while len(work) > 1:
            work = [(a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t) for a, b in zip(work, work[1:])]
        out.append(work[0])
    return out


def subpaths(d):
    toks = list(tokens(d))
    i, cmd = 0, None
    cur = start = (0.0, 0.0)
    last_ctrl = None
    poly, polys = [], []

    def num():
        nonlocal i
        v = float(toks[i])
        i += 1
        return v

    while i < len(toks):
        if toks[i].isalpha():
            cmd = toks[i]
            i += 1
            if cmd in "Zz":
                if poly:
                    polys.append(poly)
                poly, cur, last_ctrl = [], start, None
                continue
        rel = cmd.islower()
        c = cmd.upper()
        ox, oy = cur if rel else (0.0, 0.0)
        if c == "M":
            if poly:
                polys.append(poly)
            cur = start = (ox + num(), oy + num())
            poly = [cur]
            cmd = "l" if rel else "L"
            last_ctrl = None
        elif c == "L":
            cur = (ox + num(), oy + num())
            poly.append(cur)
            last_ctrl = None
        elif c == "H":
            cur = ((cur[0] if rel else 0.0) + num(), cur[1])
            poly.append(cur)
            last_ctrl = None
        elif c == "V":
            cur = (cur[0], (cur[1] if rel else 0.0) + num())
            poly.append(cur)
            last_ctrl = None
        elif c == "C":
            p1 = (ox + num(), oy + num())
            p2 = (ox + num(), oy + num())
            p3 = (ox + num(), oy + num())
            poly += bezier([cur, p1, p2, p3])
            cur, last_ctrl = p3, p2
        elif c == "S":
            p1 = (2 * cur[0] - last_ctrl[0], 2 * cur[1] - last_ctrl[1]) if last_ctrl else cur
            p2 = (ox + num(), oy + num())
            p3 = (ox + num(), oy + num())
            poly += bezier([cur, p1, p2, p3])
            cur, last_ctrl = p3, p2
        elif c == "Q":
            p1 = (ox + num(), oy + num())
            p2 = (ox + num(), oy + num())
            poly += bezier([cur, p1, p2])
            cur, last_ctrl = p2, None
        elif c == "A":
            rx, ry, phi, large, sweep = num(), num(), num(), num(), num()
            end = (ox + num(), oy + num())
            poly += arc(cur, rx, ry, phi, bool(large), bool(sweep), end)
            cur, last_ctrl = end, None
        else:
            raise SystemExit(f"unsupported path command {cmd}")
    if poly:
        polys.append(poly)
    return polys


def main():
    big = SIZE * SS
    x0, y0, span = VISIBLE
    scale = big / span
    img = Image.new("RGBA", (big, big), background_colour())
    root = ET.parse(RES / "drawable/ic_launcher_foreground.xml").getroot()
    for path in root.iter("path"):
        mask = Image.new("1", (big, big), 0)
        for poly in subpaths(path.get(A + "pathData")):
            sub = Image.new("1", (big, big), 0)
            ImageDraw.Draw(sub).polygon([((x - x0) * scale, (y - y0) * scale) for x, y in poly], fill=1)
            mask = ImageChops.logical_xor(mask, sub)
        fill = Image.new("RGBA", (big, big), colour(path.get(A + "fillColor")))
        img.paste(fill, (0, 0), mask.convert("L"))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    img.resize((SIZE, SIZE), Image.LANCZOS).convert("RGB").save(OUT, optimize=True)
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
