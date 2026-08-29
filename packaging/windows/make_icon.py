"""
Generate a professional multi-resolution Windows .ico icon for ULPF.
"""
from PIL import Image, ImageDraw
import sys
from pathlib import Path

def create_ulpf_icon(output_path: str = "packaging/windows/ulpf_icon.ico") -> None:
    size = 256
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # 1. Background rounded shield / badge
    pad = 16
    draw.rounded_rectangle(
        [pad, pad, size - pad, size - pad],
        radius=48,
        fill=(15, 23, 42, 255),  # Slate 900
        outline=(56, 189, 248, 255),  # Cyan 400
        width=8
    )

    # 2. Inner glow border
    draw.rounded_rectangle(
        [pad + 12, pad + 12, size - pad - 12, size - pad - 12],
        radius=36,
        outline=(30, 58, 138, 180),  # Blue 900 glow
        width=3
    )

    # 3. Radar grid rings
    cx, cy = size // 2, size // 2
    r1, r2, r3 = 70, 48, 26
    draw.ellipse([cx - r1, cy - r1, cx + r1, cy + r1], outline=(30, 64, 175, 120), width=2)
    draw.ellipse([cx - r2, cy - r2, cx + r2, cy + r2], outline=(14, 165, 233, 160), width=2)
    draw.ellipse([cx - r3, cy - r3, cx + r3, cy + r3], outline=(56, 189, 248, 200), width=2)

    # 4. Central telemetry node
    draw.ellipse([cx - 8, cy - 8, cx + 8, cy + 8], fill=(56, 189, 248, 255), outline=(255, 255, 255, 255), width=2)

    # 5. Log data stream status indicators
    draw.ellipse([cx + 38, cy - 30, cx + 50, cy - 18], fill=(34, 197, 94, 255))
    draw.ellipse([cx - 48, cy + 24, cx - 36, cy + 36], fill=(245, 158, 11, 255))

    # Crosshairs
    draw.line([cx - r1 - 10, cy, cx + r1 + 10, cy], fill=(14, 165, 233, 80), width=2)
    draw.line([cx, cy - r1 - 10, cx, cy + r1 + 10], fill=(14, 165, 233, 80), width=2)

    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
    img.save(str(out_file), format="ICO", sizes=sizes)
    print(f"[+] Multi-resolution Windows icon generated: {out_file.resolve()}")

if __name__ == "__main__":
    p = sys.argv[1] if len(sys.argv) > 1 else "packaging/windows/ulpf_icon.ico"
    create_ulpf_icon(p)
