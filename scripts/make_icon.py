"""Generate assets/sentry.ico and assets/sentry.png.

Design: a Windows-11-style dark rounded tile, a shield in a blue gradient,
and a white check. Everything is drawn at 4x and downscaled, so edges stay
smooth at every ico size. Re-run after tweaking; the output is committed.
"""
from __future__ import annotations

import os

from PIL import Image, ImageDraw, ImageFilter

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(os.path.dirname(HERE), "assets")

S = 1024  # working canvas (4x the largest ico frame)

TILE_TOP, TILE_BOTTOM = (27, 33, 48), (13, 15, 20)      # slate gradient
SHIELD_TOP, SHIELD_BOTTOM = (96, 165, 250), (37, 99, 235)  # blue gradient
CHECK = (255, 255, 255)


def bezier(p0, p1, p2, p3, n=60):
    for k in range(n + 1):
        t = k / n
        u = 1 - t
        yield (u**3 * p0[0] + 3 * u**2 * t * p1[0] + 3 * u * t**2 * p2[0] + t**3 * p3[0],
               u**3 * p0[1] + 3 * u**2 * t * p1[1] + 3 * u * t**2 * p2[1] + t**3 * p3[1])


def sc(pt):  # 0..1 -> canvas px
    return (pt[0] * S, pt[1] * S)


def shield_points():
    """Symmetric shield: gently arced top, sides sweeping into a bottom point."""
    pts = []
    # top edge, left -> right, with a slight upward arc
    pts += bezier((0.235, 0.215), (0.40, 0.185), (0.60, 0.185), (0.765, 0.215))
    # right side down to the bottom tip
    pts += bezier((0.765, 0.215), (0.79, 0.52), (0.665, 0.72), (0.5, 0.845))
    # left side back up (mirror)
    pts += bezier((0.5, 0.845), (0.335, 0.72), (0.21, 0.52), (0.235, 0.215))
    return [sc(p) for p in pts]


def vgrad(size, top, bottom):
    g = Image.new("RGB", (1, size))
    for y in range(size):
        t = y / (size - 1)
        g.putpixel((0, y), tuple(round(a + (b - a) * t) for a, b in zip(top, bottom)))
    return g.resize((size, size))


def rounded_mask(size, radius, inset=0):
    m = Image.new("L", (size, size), 0)
    d = ImageDraw.Draw(m)
    d.rounded_rectangle([inset, inset, size - 1 - inset, size - 1 - inset],
                        radius=radius, fill=255)
    return m


def build() -> Image.Image:
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))

    # tile
    tile = vgrad(S, TILE_TOP, TILE_BOTTOM).convert("RGBA")
    img.paste(tile, (0, 0), rounded_mask(S, radius=int(S * 0.225)))

    # soft drop shadow under the shield, for depth
    sh = Image.new("L", (S, S), 0)
    ImageDraw.Draw(sh).polygon(shield_points(), fill=110)
    sh = sh.filter(ImageFilter.GaussianBlur(S * 0.02))
    img.paste((0, 0, 0, 255), (0, int(S * 0.015)), sh)

    # shield in a vertical blue gradient
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).polygon(shield_points(), fill=255)
    img.paste(vgrad(S, SHIELD_TOP, SHIELD_BOTTOM).convert("RGBA"), (0, 0), mask)

    # check mark: thick, rounded
    d = ImageDraw.Draw(img)
    a, b, c = sc((0.375, 0.50)), sc((0.475, 0.605)), sc((0.645, 0.385))
    w = int(S * 0.062)
    d.line([a, b], fill=CHECK, width=w)
    d.line([b, c], fill=CHECK, width=w)
    for p in (a, b, c):
        d.ellipse([p[0] - w / 2, p[1] - w / 2, p[0] + w / 2, p[1] + w / 2],
                  fill=CHECK)
    return img


def main() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    art = build()
    png = os.path.join(OUT_DIR, "sentry.png")
    ico = os.path.join(OUT_DIR, "sentry.ico")
    art.resize((256, 256), Image.LANCZOS).save(png)
    art.resize((256, 256), Image.LANCZOS).save(
        ico, sizes=[(256, 256), (128, 128), (64, 64), (48, 48),
                    (32, 32), (24, 24), (16, 16)])
    print(f"wrote {ico}")
    print(f"wrote {png}")


if __name__ == "__main__":
    main()
