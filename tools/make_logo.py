"""Draws the app logo (radar sweep finding a device) and writes PNG + multi-size ICO.
Edit colours here and re-run:  python tools/make_logo.py"""
import math, os
from PIL import Image, ImageDraw, ImageFilter

S = 1024
out = os.path.join(os.path.dirname(__file__), '..', 'src', 'NetFinder', 'Assets')
os.makedirs(out, exist_ok=True)

NAVY1, NAVY2 = (14, 30, 61), (8, 72, 130)
CYAN = (56, 210, 255)
ORANGE = (255, 150, 40)

img = Image.new('RGBA', (S, S), (0, 0, 0, 0))
# rounded-square background with vertical gradient
grad = Image.new('RGBA', (S, S))
gd = ImageDraw.Draw(grad)
for y in range(S):
    t = y / S
    gd.line([(0, y), (S, y)], fill=tuple(int(NAVY1[i] * (1 - t) + NAVY2[i] * t) for i in range(3)) + (255,))
mask = Image.new('L', (S, S), 0)
ImageDraw.Draw(mask).rounded_rectangle([40, 40, S - 40, S - 40], radius=220, fill=255)
img.paste(grad, (0, 0), mask)

d = ImageDraw.Draw(img)
cx, cy = 430, 600  # radar centre (lower-left)
# radar sweep wedge
sweep = Image.new('RGBA', (S, S), (0, 0, 0, 0))
sd = ImageDraw.Draw(sweep)
for i in range(60):
    a0 = -75 + i * 0.75
    sd.pieslice([cx - 420, cy - 420, cx + 420, cy + 420], a0, a0 + 0.9, fill=CYAN + (int(4 + i * 1.6),))
sweep_masked = Image.new('RGBA', (S, S), (0, 0, 0, 0))
sweep_masked.paste(sweep, (0, 0), mask)
img = Image.alpha_composite(img, sweep_masked)
d = ImageDraw.Draw(img)
# concentric arcs
for r, w, alpha in [(140, 26, 255), (270, 24, 200), (400, 22, 140)]:
    d.arc([cx - r, cy - r, cx + r, cy + r], start=-80, end=10, fill=CYAN + (alpha,), width=w)
# centre node (this PC)
d.ellipse([cx - 52, cy - 52, cx + 52, cy + 52], fill=(255, 255, 255, 255))
d.ellipse([cx - 28, cy - 28, cx + 28, cy + 28], fill=NAVY2 + (255,))
# found device (orange, glowing) on the outer ring
ang = math.radians(-40)
fx, fy = cx + 400 * math.cos(ang), cy + 400 * math.sin(ang)
glow = Image.new('RGBA', (S, S), (0, 0, 0, 0))
ImageDraw.Draw(glow).ellipse([fx - 110, fy - 110, fx + 110, fy + 110], fill=ORANGE + (170,))
glow = glow.filter(ImageFilter.GaussianBlur(40))
img = Image.alpha_composite(img, glow)
d = ImageDraw.Draw(img)
d.ellipse([fx - 62, fy - 62, fx + 62, fy + 62], fill=ORANGE + (255,))
d.ellipse([fx - 26, fy - 26, fx + 26, fy + 26], fill=(255, 255, 255, 255))
# dashed link between PC and found device
steps = 9
for i in range(1, steps):
    if i % 2: continue
for i in range(steps):
    t0, t1 = i / steps, (i + 0.5) / steps
    if t0 < 0.15 or t1 > 0.85: continue
    d.line([(cx + (fx - cx) * t0, cy + (fy - cy) * t0), (cx + (fx - cx) * t1, cy + (fy - cy) * t1)], fill=(255, 255, 255, 200), width=14)

img.save(os.path.join(out, 'logo-1024.png'))
img.resize((256, 256), Image.LANCZOS).save(os.path.join(out, 'logo-256.png'))
img.save(os.path.join(out, 'app.ico'), sizes=[(16, 16), (20, 20), (24, 24), (32, 32), (40, 40), (48, 48), (64, 64), (128, 128), (256, 256)])
print('logo written to', os.path.abspath(out))
