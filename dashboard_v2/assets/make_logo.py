"""SeSAC Security 로고 PNG 생성 (투명 배경, 3배 해상도로 그린 뒤 축소).

실행: python dashboard_v2/assets/make_logo.py
출력: sesac_security_logo_light.png (밝은 글자, 파란 배너·어두운 배경용)
      sesac_security_logo_dark.png  (네이비 글자, 흰 배경용)
"""
import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont

OUT = Path(__file__).resolve().parent
S = 3                      # 그리는 배율
W, H = 760 * S, 180 * S    # 최종 760×180
CYAN, SKY, BLUE, NAVY = (47, 224, 247), (26, 163, 255), (11, 91, 224), (6, 42, 122)
FONT_BOLD = "C:/Windows/Fonts/segoeuib.ttf"
FONT_LIGHT = "C:/Windows/Fonts/segoeuisl.ttf"


def hexagon(cx, cy, r):
    return [(cx + r * math.cos(math.radians(60 * i - 90)), cy + r * math.sin(math.radians(60 * i - 90))) for i in range(6)]


def gradient(size, c1, c2):
    """왼쪽 위 → 오른쪽 아래 그라데이션."""
    w, h = size
    g = Image.new("RGBA", size)
    px = g.load()
    for y in range(h):
        for x in range(w):
            t = (x / w + y / h) / 2
            px[x, y] = tuple(int(a + (b - a) * t) for a, b in zip(c1, c2)) + (255,)
    return g


def mark(size):
    """육각형 방패 마크: 그라데이션 육각형 + 안쪽 육각형 테두리 + 노드 3개와 연결선."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    c, r = size / 2, size * 0.46
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).polygon(hexagon(c, c, r), fill=255)
    img.paste(gradient((size, size), CYAN, BLUE), (0, 0), mask)
    d = ImageDraw.Draw(img)
    d.polygon(hexagon(c, c, r * 0.62), outline=(255, 255, 255, 235), width=int(size * 0.035))
    # 네트워크 노드 (안쪽 육각형 꼭짓점 세 곳) → 중심으로 연결
    pts = [hexagon(c, c, r * 0.62)[i] for i in (0, 2, 4)]
    for x, y in pts:
        d.line([(x, y), (c, c)], fill=(255, 255, 255, 200), width=int(size * 0.025))
    for x, y in pts + [(c, c)]:
        rr = size * 0.045
        d.ellipse([x - rr, y - rr, x + rr, y + rr], fill=(255, 255, 255, 255))
    return img


def logo(text_main, text_sub, tag):
    canvas = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    m = mark(int(H * 0.86))
    glow = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    gm = Image.new("RGBA", m.size, CYAN + (150,))
    glow.paste(gm, (int(H * 0.07), int(H * 0.07)), m)
    canvas = Image.alpha_composite(canvas, glow.filter(ImageFilter.GaussianBlur(10 * S)))
    canvas.alpha_composite(m, (int(H * 0.07), int(H * 0.07)))

    d = ImageDraw.Draw(canvas)
    x = int(H * 1.02)
    f_main = ImageFont.truetype(FONT_BOLD, 78 * S)
    f_sub = ImageFont.truetype(FONT_LIGHT, 64 * S)
    f_tag = ImageFont.truetype(FONT_BOLD, 19 * S)
    y = int(H * 0.12)
    d.text((x, y), "SeSAC", font=f_main, fill=text_main)
    w_sesac = d.textlength("SeSAC ", font=f_main)
    d.text((x + w_sesac, y + 10 * S), "Security", font=f_sub, fill=text_sub)
    total = w_sesac + d.textlength("Security", font=f_sub)
    # 아래 구분선(그라데이션) + 작은 영문 태그
    ly = int(H * 0.70)
    bar = gradient((int(total), int(4 * S)), CYAN, BLUE)
    canvas.alpha_composite(bar, (x, ly))
    d.text((x, ly + 10 * S), "LOG ANALYTICS  ·  THREAT DETECTION", font=f_tag, fill=tag)
    return canvas.resize((W // S, H // S), Image.LANCZOS)


logo((255, 255, 255, 255), (190, 238, 255, 255), (200, 228, 255, 230)).save(OUT / "sesac_security_logo_light.png")
logo(NAVY + (255,), BLUE + (255,), (90, 107, 133, 255)).save(OUT / "sesac_security_logo_dark.png")
print("saved", OUT)
