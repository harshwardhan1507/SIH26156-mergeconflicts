"""
Generate all official ULPF branding assets:
- SVG Logos (Horizontal, Square, Badge)
- PNG Icons (16x16, 32x32, 64x64, 128x128, 256x256, 512x512)
- Multi-resolution Windows .ico
- Favicon for web dashboard
"""
import os
import shutil
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

SVG_BADGE = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="100%" height="100%">
  <defs>
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0f172a" />
      <stop offset="100%" stop-color="#020617" />
    </linearGradient>
    <linearGradient id="primaryGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#06b6d4" />
      <stop offset="50%" stop-color="#0ea5e9" />
      <stop offset="100%" stop-color="#3b82f6" />
    </linearGradient>
    <linearGradient id="accentGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#14b8a6" />
      <stop offset="100%" stop-color="#06b6d4" />
    </linearGradient>
    <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="3" result="blur" />
      <feComposite in="SourceGraphic" in2="blur" operator="over" />
    </filter>
  </defs>

  <!-- Base Hexagonal / Shield Container -->
  <rect x="6" y="6" width="116" height="116" rx="28" fill="url(#bgGrad)" stroke="#1e293b" stroke-width="3"/>
  <rect x="10" y="10" width="108" height="108" rx="24" fill="none" stroke="url(#primaryGrad)" stroke-width="2" opacity="0.6"/>

  <!-- Radar / Telemetry Grid Circles -->
  <circle cx="64" cy="64" r="44" fill="none" stroke="#1e293b" stroke-width="1.5" stroke-dasharray="4 4"/>
  <circle cx="64" cy="64" r="30" fill="none" stroke="#0ea5e9" stroke-width="1" opacity="0.4"/>
  <circle cx="64" cy="64" r="16" fill="none" stroke="#14b8a6" stroke-width="1.5" opacity="0.6"/>

  <!-- Crosshair Guides -->
  <line x1="16" y1="64" x2="112" y2="64" stroke="#0ea5e9" stroke-width="1" opacity="0.25"/>
  <line x1="64" y1="16" x2="64" y2="112" stroke="#0ea5e9" stroke-width="1" opacity="0.25"/>

  <!-- Stylized Telemetry Shield / U-Core -->
  <path d="M40 38 v34 c0 13.25 10.75 24 24 24 s24 -10.75 24 -24 V38" fill="none" stroke="url(#primaryGrad)" stroke-width="8" stroke-linecap="round" stroke-linejoin="round" filter="url(#glow)"/>
  
  <!-- Central Pulse Node -->
  <circle cx="64" cy="64" r="6" fill="#ffffff" filter="url(#glow)"/>
  <circle cx="64" cy="64" r="3" fill="#06b6d4"/>

  <!-- Real-time Status Stream Beacons -->
  <circle cx="92" cy="42" r="4.5" fill="#10b981" filter="url(#glow)"/>
  <circle cx="36" cy="86" r="4" fill="#f59e0b" opacity="0.9"/>
  <circle cx="40" cy="38" r="4" fill="#ffffff"/>
  <circle cx="88" cy="38" r="4" fill="#ffffff"/>
</svg>
"""

SVG_HORIZONTAL_BANNER = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 520 80" width="100%" height="100%">
  <defs>
    <linearGradient id="bannerBg" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#0f172a" />
      <stop offset="100%" stop-color="#020617" />
    </linearGradient>
    <linearGradient id="textGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#38bdf8" />
      <stop offset="50%" stop-color="#818cf8" />
      <stop offset="100%" stop-color="#c084fc" />
    </linearGradient>
    <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#06b6d4" />
      <stop offset="100%" stop-color="#3b82f6" />
    </linearGradient>
  </defs>

  <rect width="520" height="80" rx="16" fill="url(#bannerBg)" stroke="#1e293b" stroke-width="2"/>

  <!-- Logo Mark Group -->
  <g transform="translate(16, 12)">
    <rect x="0" y="0" width="56" height="56" rx="14" fill="#1e293b" stroke="url(#shieldGrad)" stroke-width="2"/>
    <path d="M18 16 v16 c0 6 4.5 10.5 10 10.5 s10 -4.5 10 -10.5 V16" fill="none" stroke="url(#shieldGrad)" stroke-width="4.5" stroke-linecap="round"/>
    <circle cx="28" cy="28" r="3" fill="#ffffff"/>
    <circle cx="28" cy="28" r="1.5" fill="#06b6d4"/>
    <circle cx="42" cy="18" r="2.5" fill="#10b981"/>
  </g>

  <!-- Typography -->
  <text x="88" y="38" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="24" font-weight="800" fill="#f8fafc" letter-spacing="1">ULPF</text>
  <text x="162" y="38" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="14" font-weight="600" fill="#94a3b8" letter-spacing="0.5">OPERATIONS PLATFORM</text>
  <text x="88" y="58" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="12" font-weight="400" fill="#64748b">Universal Log Pre-processing &amp; Forensic Normalization Engine</text>
</svg>
"""

def generate_png_from_pil(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    pad = int(size * 0.05)
    r = int(size * 0.22)
    # Background rounded container
    draw.rounded_rectangle(
        [pad, pad, size - pad, size - pad],
        radius=r,
        fill=(15, 23, 42, 255),
        outline=(14, 165, 233, 255),
        width=max(2, int(size * 0.03))
    )

    cx, cy = size // 2, size // 2

    # Radar rings
    r1 = int(size * 0.35)
    r2 = int(size * 0.23)
    draw.ellipse([cx - r1, cy - r1, cx + r1, cy + r1], outline=(30, 58, 138, 140), width=max(1, int(size * 0.015)))
    draw.ellipse([cx - r2, cy - r2, cx + r2, cy + r2], outline=(14, 165, 233, 180), width=max(1, int(size * 0.02)))

    # Crosshairs
    draw.line([cx - r1, cy, cx + r1, cy], fill=(14, 165, 233, 80), width=max(1, int(size * 0.015)))
    draw.line([cx, cy - r1, cx, cy + r1], fill=(14, 165, 233, 80), width=max(1, int(size * 0.015)))

    # U Core Shape
    u_w = int(size * 0.38)
    u_h = int(size * 0.46)
    stroke_w = max(3, int(size * 0.075))
    x0, y0 = cx - u_w // 2, cy - u_h // 2
    x1, y1 = cx + u_w // 2, cy + u_h // 2

    # Vertical left & right
    corner_r = int(u_w // 2)
    # Draw U using arc and lines
    draw.arc([x0, y1 - corner_r * 2, x1, y1], start=0, end=180, fill=(56, 189, 248, 255), width=stroke_w)
    draw.line([x0, y0, x0, y1 - corner_r], fill=(56, 189, 248, 255), width=stroke_w)
    draw.line([x1, y0, x1, y1 - corner_r], fill=(56, 189, 248, 255), width=stroke_w)

    # Center node
    node_r = max(2, int(size * 0.05))
    draw.ellipse([cx - node_r, cy - node_r, cx + node_r, cy + node_r], fill=(255, 255, 255, 255), outline=(6, 182, 212, 255), width=max(1, int(size * 0.015)))

    # Status beacon
    b_r = max(2, int(size * 0.035))
    draw.ellipse([cx + int(size*0.22) - b_r, cy - int(size*0.18) - b_r, cx + int(size*0.22) + b_r, cy - int(size*0.18) + b_r], fill=(16, 185, 129, 255))

    return img

def main():
    root = Path(__file__).parent.parent.resolve()
    print(f"[*] Generating official branding and logo assets in {root}...")

    # 1. Write SVGs
    dash_static = root / "ulpf" / "dashboard" / "static"
    dash_static.mkdir(parents=True, exist_ok=True)
    docs_dir = root / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    pkg_win = root / "packaging" / "windows"
    pkg_win.mkdir(parents=True, exist_ok=True)

    (dash_static / "ulpf-logo.svg").write_text(SVG_BADGE, encoding="utf-8")
    (dash_static / "favicon.svg").write_text(SVG_BADGE, encoding="utf-8")
    (docs_dir / "ulpf-icon.svg").write_text(SVG_BADGE, encoding="utf-8")
    (docs_dir / "ulpf-banner.svg").write_text(SVG_HORIZONTAL_BANNER, encoding="utf-8")

    # 2. Generate multi-resolution PNGs
    img_512 = generate_png_from_pil(512)
    img_256 = generate_png_from_pil(256)
    img_128 = generate_png_from_pil(128)
    img_64 = generate_png_from_pil(64)
    img_32 = generate_png_from_pil(32)
    img_16 = generate_png_from_pil(16)

    img_256.save(str(dash_static / "favicon.png"), format="PNG")
    img_256.save(str(dash_static / "ulpf_logo.png"), format="PNG")
    img_256.save(str(pkg_win / "ulpf_icon.png"), format="PNG")
    img_512.save(str(docs_dir / "ulpf_logo_512.png"), format="PNG")

    # 3. Generate Windows .ICO with all standard icon sizes
    ico_path = pkg_win / "ulpf_icon.ico"
    img_256.save(
        str(ico_path),
        format="ICO",
        sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
    )
    shutil.copy2(ico_path, dash_static / "favicon.ico")

    print("[+] Created vector SVG logos (Square, Horizontal, Favicon)")
    print(f"[+] Created Windows multi-resolution icon: {ico_path}")
    print(f"[+] Created web dashboard favicon and logo: {dash_static / 'favicon.ico'}")
    print("[SUCCESS] All logos and assets generated!")

if __name__ == "__main__":
    main()
