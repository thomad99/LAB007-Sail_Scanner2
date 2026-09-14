"""Crop the 5 Love Sailing menu icon tiles from the ChatGPT sprite."""
from pathlib import Path
from PIL import Image

SPRITE = Path(
    r"C:\Users\tomo\.cursor\projects\c-Users-tomo-Documents-AI-3-1-ScanImage"
    r"\assets\c__Users_tomo_AppData_Roaming_Cursor_User_workspaceStorage_"
    r"b7439d6e455c2899860d16d333ec2111_images_ChatGPT_Image_Sep_13__2026__"
    r"09_43_01_PM-a85a6f64-189a-4dd3-8f51-03cc47d3e9b5.png"
)
OUT_DIR = Path(r"C:\Users\tomo\Documents\AI\3.1-ScanImage\public\Images")
PAGE_NAVY = (2, 0, 83)  # #020053
NAMES = [
    "icon-sailbot.png",
    "icon-photos.png",
    "icon-regatta-search.png",
    "icon-tracker.png",
    "icon-shopping.png",
]


def lum(c):
    return (c[0] + c[1] + c[2]) / 3.0


def is_page_bg(c):
    """True for the sprite's dark navy canvas (not glow or icon strokes)."""
    r, g, b = c[:3]
    return lum((r, g, b)) < 42 and b < 80


def main():
    src = Image.open(SPRITE).convert("RGB")
    w, h = src.size
    px = src.load()

    # Labels sit below ~y=240. Detect tiles in the icon band only.
    y_lo, y_hi = 80, 236
    col_max = [0] * w
    for x in range(w):
        m = 0
        for y in range(y_lo, y_hi):
            v = lum(px[x, y])
            if v > m:
                m = v
        col_max[x] = m

    runs = []
    in_run = False
    for x, v in enumerate(col_max):
        if v > 70:
            if not in_run:
                start = x
                in_run = True
        elif in_run:
            runs.append((start, x - 1))
            in_run = False
    if in_run:
        runs.append((start, w - 1))

    if len(runs) != 5:
        raise SystemExit(f"expected 5 tiles, found {len(runs)}: {runs}")

    boxes = []
    for x0, x1 in runs:
        ys = []
        for y in range(y_lo, y_hi):
            m = 0
            for x in range(x0, x1 + 1, 2):
                v = lum(px[x, y])
                if v > m:
                    m = v
            if m > 70:
                ys.append(y)
        boxes.append((x0, ys[0], x1, ys[-1]))

    max_w = max(x1 - x0 + 1 for x0, y0, x1, y1 in boxes)
    max_h = max(y1 - y0 + 1 for x0, y0, x1, y1 in boxes)
    pad = 10
    crop_w = max_w + pad * 2
    crop_h = max_h + pad * 2
    # Equal square tiles
    side = max(crop_w, crop_h)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"sprite {w}x{h}  tiles {boxes}  equal {side}x{side}")

    for name, (x0, y0, x1, y1) in zip(NAMES, boxes):
        cx = (x0 + x1) / 2.0
        cy = (y0 + y1) / 2.0
        left = int(round(cx - side / 2.0))
        top = int(round(cy - side / 2.0))
        left = max(0, min(left, w - side))
        top = max(0, min(top, h - side))
        right = left + side
        bottom = top + side
        tile = src.crop((left, top, right, bottom)).convert("RGBA")
        tpx = tile.load()
        tw, th = tile.size
        for yy in range(th):
            for xx in range(tw):
                r, g, b, a = tpx[xx, yy]
                if is_page_bg((r, g, b)):
                    tpx[xx, yy] = (*PAGE_NAVY, 255)
        dest = OUT_DIR / name
        tile.save(dest, "PNG")
        print(f"wrote {dest.name}  box=({left},{top},{right},{bottom})  {tw}x{th}")


if __name__ == "__main__":
    main()
