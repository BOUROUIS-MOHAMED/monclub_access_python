# Access tray menu icons

16x16 RGBA PNGs for the access tray right-click menu (`src/lib.rs`, `build_access_tray_menu`).
Lucide shapes named in the v5 design (`docs/access-redesign-v5/src/win.logic.js`, tray menu), path data
from that design's `icons.json`, stroke width 2 on the 24 grid, colour #637381 (the design's menu icon grey).
Rendered at 64 px with headless Edge, alpha downscaled to 16 px with Pillow, colour kept flat.

16 px because muda draws every Windows menu bitmap into a fixed 16x16 rect.
New files only: the TV build's icons in `icons/` are not used or changed here.
