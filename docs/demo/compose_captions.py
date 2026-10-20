"""Burn professional lower-third captions into the recorded walkthrough and encode the final MP4.

    python docs/demo/compose_captions.py --rec docs/demo/build/record --out docs/demo/ZeroTrustVault-demo.mp4
"""
from __future__ import annotations

import argparse
import json
import subprocess
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[2]
W, H = 1920, 1080  # overridden from captions.json
BAR_H = 150
SCALE = 1.0


def font(size: int, bold: bool = False):
    for c in (["C:/Windows/Fonts/segoeuib.ttf"] if bold else ["C:/Windows/Fonts/segoeui.ttf"]) + ["C:/Windows/Fonts/arial.ttf"]:
        if Path(c).exists():
            return ImageFont.truetype(c, size)
    return ImageFont.load_default()


def render_caption(text: str, path: Path) -> None:
    """Lower third: translucent dark band with a thin accent line, white text up to two lines."""
    im = Image.new("RGBA", (W, BAR_H), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    s = SCALE
    for y in range(BAR_H):  # gradient band
        a = int(min(1.0, y / (18 * s)) * 190)
        d.line((0, y, W, y), fill=(8, 11, 20, a))
    d.rectangle((int(40 * s), int(30 * s), int(44 * s), BAR_H - int(24 * s)), fill=(99, 128, 255, 255))
    f = font(int(23 * s))
    lines = textwrap.wrap(text, 92)[:2]
    y = int((34 if len(lines) > 1 else 44) * s)
    for line in lines:
        d.text((int(58 * s), y), line, font=f, fill=(240, 243, 250, 255))
        y += int(32 * s)
    im.save(path)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rec", default=str(ROOT / "docs" / "demo" / "build" / "record"))
    ap.add_argument("--out", default=str(ROOT / "docs" / "demo" / "ZeroTrustVault-demo.mp4"))
    ap.add_argument("--offset", type=float, default=0.0, help="shift captions (s) if the video clock leads/lags")
    a = ap.parse_args(argv)
    import imageio_ffmpeg

    ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
    rec = Path(a.rec)
    meta = json.loads((rec / "captions.json").read_text())
    global W, H, BAR_H, SCALE
    W, H = int(meta.get("width", 1280)), int(meta.get("height", 720))
    SCALE = W / 1280.0
    BAR_H = int(112 * SCALE)
    video = Path(meta["video"])
    caps = meta["captions"]
    duration = float(meta["duration"])
    capdir = rec / "caps"
    capdir.mkdir(exist_ok=True)

    inputs = ["-i", str(video)]
    chains = []
    prev = "[0:v]"
    for i, c in enumerate(caps):
        png = capdir / f"cap{i:02d}.png"
        render_caption(c["text"], png)
        inputs += ["-i", str(png)]
        start = max(0.0, c["t"] + a.offset)
        end = (caps[i + 1]["t"] + a.offset) if i + 1 < len(caps) else duration + 2
        end = max(start + 0.5, end - 0.15)
        out = f"[v{i}]"
        chains.append(f"{prev}[{i + 1}:v]overlay=0:{H - BAR_H}:enable='between(t,{start:.2f},{end:.2f})'{out}")
        prev = out
    filter_complex = ";".join(chains)
    cmd = [ffmpeg, "-y", "-loglevel", "error", *inputs, "-filter_complex", filter_complex, "-map", prev,
           "-r", "30", "-c:v", "libx264", "-preset", "slow", "-crf", "17", "-profile:v", "high", "-level", "4.1", "-pix_fmt", "yuv420p", "-movflags", "+faststart", "-an", str(a.out)]
    subprocess.run(cmd, check=True)
    size = Path(a.out).stat().st_size / 1e6
    print(f"wrote {a.out}  ({duration/60:.1f} min, {size:.1f} MB, {len(caps)} captions)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
