from __future__ import annotations

from pathlib import Path
from PIL import Image


# Inno Setup modern wizard common sizes
WIZARD_BIG = (164, 314)     # WizardImageFile
WIZARD_SMALL = (55, 58)     # WizardSmallImageFile


def contain(img: Image.Image, size: tuple[int, int], bg=(255, 255, 255)) -> Image.Image:
    """
    Resize to fit within 'size' (preserve aspect ratio) and center on background.
    """
    img = img.convert("RGBA")

    # compute scale
    iw, ih = img.size
    tw, th = size
    scale = min(tw / iw, th / ih)
    nw, nh = max(1, int(iw * scale)), max(1, int(ih * scale))
    resized = img.resize((nw, nh), Image.LANCZOS)

    # background
    canvas = Image.new("RGBA", size, bg + (255,))
    x = (tw - nw) // 2
    y = (th - nh) // 2
    canvas.alpha_composite(resized, (x, y))
    return canvas.convert("RGB")  # BMP wants RGB


def main() -> None:
    repo = Path(__file__).resolve().parents[1]
    src = repo / "installer" / "assets" / "monclub_logo.png"

    out_dir = repo / "installer" / "assets"
    out_dir.mkdir(parents=True, exist_ok=True)

    if not src.exists():
        raise SystemExit(f"Missing input file: {src}")

    img = Image.open(src)

    big = contain(img, WIZARD_BIG, bg=(255, 255, 255))
    small = contain(img, WIZARD_SMALL, bg=(255, 255, 255))

    big_path = out_dir / "wizard.bmp"
    small_path = out_dir / "wizard_small.bmp"

    # BMP defaults are fine; save as 24-bit BMP
    big.save(big_path, format="BMP")
    small.save(small_path, format="BMP")

    print("Generated:")
    print(f" - {big_path}")
    print(f" - {small_path}")


if __name__ == "__main__":
    main()
