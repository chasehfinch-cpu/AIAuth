"""
Generates the AIAuth logo: blue rounded-square background with 'AIA' in white,
outer A's tilted to lean against the central I.
"""
import math
from PIL import Image, ImageDraw

CANVAS = 1024
RADIUS = 220
BG = (37, 99, 235)        # #2563eb
FG = (255, 255, 255)
STROKE = 86               # letter stroke width


def rotate(pt, center, deg):
    x, y = pt
    cx, cy = center
    t = math.radians(deg)
    return (
        cx + (x - cx) * math.cos(t) - (y - cy) * math.sin(t),
        cy + (x - cx) * math.sin(t) + (y - cy) * math.cos(t),
    )


def draw_letter_A(draw, cx, cy, height, lean=0, stroke=STROKE):
    """A with flat feet planted on the ground; apex shifted horizontally by `lean` (px)."""
    w = height * 0.66
    baseline_y = cy + height / 2
    top_y = cy - height / 2
    # End legs slightly above baseline so the rounded stroke cap doesn't poke past the foot serif.
    leg_end_y = baseline_y - stroke * 0.28
    left_foot = (cx - w / 2, leg_end_y)
    right_foot = (cx + w / 2, leg_end_y)
    top = (cx + lean, top_y)
    crossbar_y = cy + height * 0.14
    t = (crossbar_y - top_y) / (baseline_y - top_y)
    cb_left = (top[0] + (left_foot[0] - top[0]) * t, crossbar_y)
    cb_right = (top[0] + (right_foot[0] - top[0]) * t, crossbar_y)

    draw.line([left_foot, top], fill=FG, width=stroke, joint="curve")
    draw.line([top, right_foot], fill=FG, width=stroke, joint="curve")
    draw.line([cb_left, cb_right], fill=FG, width=int(stroke * 0.85))
    # Round apex so the two legs merge cleanly
    r = stroke // 2
    draw.ellipse([top[0] - r, top[1] - r, top[0] + r, top[1] + r], fill=FG)
    # Flat serif "feet" on the baseline (drawn after the legs so they cover the leg ends)
    serif_w = stroke * 1.65
    serif_h = stroke * 0.48
    for foot in (left_foot, right_foot):
        draw.rectangle(
            [foot[0] - serif_w / 2, baseline_y - serif_h,
             foot[0] + serif_w / 2, baseline_y],
            fill=FG,
        )


def draw_letter_I(draw, cx, cy, height, stroke=STROKE):
    """Vertical stem with top and bottom serifs."""
    half_h = height / 2
    stem_w = stroke
    # Stem
    draw.rectangle(
        [cx - stem_w / 2, cy - half_h, cx + stem_w / 2, cy + half_h],
        fill=FG,
    )
    # Serifs
    serif_w = stroke * 1.8
    serif_h = stroke * 0.55
    for sy in (cy - half_h, cy + half_h - serif_h):
        draw.rectangle(
            [cx - serif_w / 2, sy, cx + serif_w / 2, sy + serif_h],
            fill=FG,
        )


def rounded_rect_mask(size, radius):
    m = Image.new("L", (size, size), 0)
    d = ImageDraw.Draw(m)
    d.rounded_rectangle([0, 0, size, size], radius=radius, fill=255)
    return m


def build():
    img = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))
    # Blue rounded-square background
    bg = Image.new("RGBA", (CANVAS, CANVAS), BG + (255,))
    mask = rounded_rect_mask(CANVAS, RADIUS)
    img.paste(bg, (0, 0), mask)

    draw = ImageDraw.Draw(img)

    h = int(CANVAS * 0.48)
    cy = CANVAS // 2
    gap = int(CANVAS * 0.26)  # distance from center to each A's base-center

    # Draw A's first, then I on top so it sits in front like a pillar
    lean = int(h * 0.11)  # apex shift toward the I
    draw_letter_A(draw, CANVAS // 2 - gap, cy, h, lean=lean)
    draw_letter_A(draw, CANVAS // 2 + gap, cy, h, lean=-lean)
    draw_letter_I(draw, CANVAS // 2, cy, h)

    return img


def main():
    master = build()
    master.save("icon1024.png")
    for size in (16, 48, 128):
        resized = master.resize((size, size), Image.LANCZOS)
        resized.save(f"icon{size}.png")
    print("Generated icon16.png, icon48.png, icon128.png, icon1024.png")


if __name__ == "__main__":
    main()
