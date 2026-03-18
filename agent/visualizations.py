"""
Static analysis visualizations embedded as base64 PNG in the report.
Four charts:
  1. Entropy profile   — sliding-window Shannon entropy across the file
  2. Compression curve — zlib/bz2/lzma ratio vs compression level (binary only)
  3. Bigram matrix     — byte-pair transition heatmap (256×256 binary / 95×95 ASCII-filtered for text)
  4. Trigram scatter   — 3-gram point cloud projected via PCA

file_mode="binary" : PE, ELF, Office, PDF, LNK, MSI, archives
file_mode="text"   : PS1, JS, VBS, HTA, shell scripts, batch
"""
import math
import zlib
import bz2
import lzma
import base64
from io import BytesIO
from typing import Dict, Any, Callable, Optional

_MAX_BYTES = 1 * 1024 * 1024  # 1 MB cap

BG     = '#0d1117'
GREEN  = '#2ad67c'
RED    = '#ff4d4d'
YELLOW = '#f0c64a'
ORANGE = '#f0a500'
MUTED  = '#8b949e'

# Printable ASCII range used for text-mode filtering
_ASCII_LO = 0x20
_ASCII_HI = 0x7E
_ASCII_N  = _ASCII_HI - _ASCII_LO + 1  # 95 chars


def _save_fig(fig) -> str:
    buf = BytesIO()
    fig.savefig(buf, format='png', bbox_inches='tight', dpi=200,
                facecolor=BG, edgecolor='none')
    buf.seek(0)
    return base64.b64encode(buf.read()).decode()


def _style_ax(ax):
    ax.set_facecolor(BG)
    ax.tick_params(colors=MUTED, labelsize=6)
    for spine in ax.spines.values():
        spine.set_edgecolor('#30363d')
        spine.set_linewidth(0.6)


# ---------------------------------------------------------------------------
# LLM interpretation contexts — plain text sent in the prompt
# ---------------------------------------------------------------------------

_CHART_CONTEXTS = {
    "binary": {
        "entropy profile": (
            "Shannon entropy per 256-byte sliding window, calibrated for binary files. "
            "Green (<5 bits/byte) = structured code or data; yellow (5–7) = compressed regions; "
            "red (≥7) = encrypted, packed, or high-entropy shellcode. "
            "Malware often shows extended flat red plateaus (encrypted payloads, packed sections). "
            "Benign binaries show heterogeneous entropy with visible section-boundary transitions."
        ),
        "compression curve": (
            "Compressed size ÷ original size across increasing levels of zlib, bz2, and lzma. "
            "Curves staying near 1.0 (red dashed line ≥0.95) mean the file resists compression — "
            "a strong indicator of encryption, packing, or high-entropy shellcode. "
            "Benign executables contain large structured/repeated regions and compress significantly. "
            "Encrypted payloads stay flat near 1.0 regardless of algorithm or effort level."
        ),
        "byte bigram matrix": (
            "256×256 heatmap (log scale) of byte-pair transition frequencies for the full binary. "
            "Benign PE/ELF files show a dominant bright cluster at (0x00,0x00) from null-byte padding, "
            "dense patches in the 0x20–0x7F ASCII range from strings and import names, and isolated hot "
            "spots at common x86 opcode-pair transitions. "
            "Encrypted or random data produces a near-uniform bright grid — maximum byte-transition entropy."
        ),
        "byte trigram scatter (PCA)": (
            "Each byte triple (b[i], b[i+1], b[i+2]) is a point in 3-D space projected to 2-D via PCA; "
            "colour encodes HDBSCAN density cluster (grey = noise, distinct colours = separate clusters). "
            "HDBSCAN adapts to local density — no fixed epsilon; clusters reflect true density structure. "
            "Benign binaries produce a small number of tight, well-separated clusters (repeated instruction patterns). "
            "Encrypted or random data produces no cluster structure — everything is noise (grey)."
        ),
    },
    "text": {
        "entropy profile": (
            "Shannon entropy per 256-byte sliding window, calibrated for interpreted/text files. "
            "Unlike binary executables, plain text has a natural entropy of 4–5 bits/byte. "
            "Green (<4 bits/byte) = highly repetitive or structured text (padding, loops); "
            "yellow (4–5.5) = normal source code or script content — THIS IS THE EXPECTED BENIGN RANGE; "
            "red (≥5.5) = obfuscated content, embedded base64 blobs, or encoded payloads. "
            "Malicious scripts often show isolated high-entropy spikes against an otherwise "
            "yellow/green baseline. A flat green/yellow profile with no red spikes is benign."
        ),
        "byte bigram matrix": (
            "95×95 bigram heatmap restricted to printable ASCII characters (0x20–0x7E), log scale. "
            "By filtering to the printable range the matrix shows character-pair transition frequencies "
            "within the script's actual text content. "
            "Benign source code shows structured clusters at common syntax pairs "
            "(parentheses, operators, alphanumeric identifiers, whitespace). "
            "Obfuscated scripts produce a more uniform fill within this space — "
            "a near-uniform bright grid indicates randomised character sequences consistent with "
            "obfuscation, random variable names, or base64 encoding."
        ),
        "byte trigram scatter (PCA)": (
            "Trigram (3-gram) scatter restricted to printable ASCII bytes (0x20–0x7E), projected via PCA. "
            "Colour encodes HDBSCAN density cluster (grey = noise, distinct colours = separate clusters). "
            "HDBSCAN adapts to local density — no fixed epsilon. "
            "Benign source code forms a small number of tight clusters around repeated syntax patterns "
            "(keywords, brackets, common operator sequences). "
            "Obfuscated or randomised scripts produce a diffuse, near-isotropic scatter with no distinct clusters."
        ),
    },
}


# ---------------------------------------------------------------------------
# Chart functions
# ---------------------------------------------------------------------------

def entropy_profile_chart(data: bytes, file_mode: str = "binary") -> Dict[str, Any]:
    """Sliding-window Shannon entropy. Thresholds adapt to file_mode."""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
        from matplotlib.collections import LineCollection

        data = data[:_MAX_BYTES]
        block_size = 256
        if len(data) < block_size:
            return {"ok": False, "error": "file too small"}

        entropies = []
        for i in range(0, len(data) - block_size + 1, block_size):
            block = data[i:i + block_size]
            counts = [0] * 256
            for b in block:
                counts[b] += 1
            h = 0.0
            for c in counts:
                if c > 0:
                    p = c / block_size
                    h -= p * math.log2(p)
            entropies.append(h)

        if len(entropies) > 512:
            step = len(entropies) // 512
            entropies = entropies[::step]

        xs = np.linspace(0, 100, len(entropies))

        # Thresholds differ by file mode
        if file_mode == "text":
            lo_thresh, hi_thresh = 4.0, 5.5
            lo_label = f"{lo_thresh} (structured text)"
            hi_label = f"{hi_thresh} (obfuscated/encoded)"
            y_max = 7.0
        else:
            lo_thresh, hi_thresh = 5.0, 7.0
            lo_label = f"{lo_thresh} (compressed)"
            hi_label = f"{hi_thresh} (encrypted)"
            y_max = 8.2

        fig, ax = plt.subplots(figsize=(4.2, 2.0))
        fig.patch.set_facecolor(BG)
        _style_ax(ax)

        pts = np.array([xs, entropies]).T.reshape(-1, 1, 2)
        segs = np.concatenate([pts[:-1], pts[1:]], axis=1)
        seg_colors = [RED if e >= hi_thresh else YELLOW if e >= lo_thresh else GREEN
                      for e in entropies[:-1]]
        from matplotlib.collections import LineCollection as LC
        lc = LC(segs, colors=seg_colors, linewidth=1.4)
        ax.add_collection(lc)

        ax.axhline(hi_thresh, color=RED,    linewidth=0.6, linestyle='--', alpha=0.45, label=hi_label)
        ax.axhline(lo_thresh, color=YELLOW, linewidth=0.6, linestyle='--', alpha=0.45, label=lo_label)

        ax.set_xlim(0, 100)
        ax.set_ylim(0, y_max)
        ax.set_xlabel('File offset (%)', color=MUTED, fontsize=7)
        ax.set_ylabel('Entropy (bits/byte)', color=MUTED, fontsize=7)
        ax.legend(fontsize=5.5, facecolor='#161b22', edgecolor='#30363d',
                  labelcolor=MUTED, loc='lower right')

        plt.tight_layout(pad=0.4)
        b64 = _save_fig(fig)
        plt.close(fig)
        return {"ok": True, "b64": b64}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def compression_curve_chart(data: bytes, file_mode: str = "binary") -> Dict[str, Any]:
    """Compression ratio curve. Skipped for text files."""
    if file_mode == "text":
        return {
            "ok": False,
            "skipped": True,
            "reason": "Not meaningful for text/interpreted files — all plain text compresses well regardless of content.",
        }
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt

        data = data[:_MAX_BYTES]
        if len(data) == 0:
            return {"ok": False, "error": "empty file"}

        orig = len(data)
        levels = list(range(1, 10))
        zlib_r = [len(zlib.compress(data, lvl)) / orig for lvl in levels]
        bz2_r  = [len(bz2.compress(data, lvl))  / orig for lvl in levels]
        lzma_pts = []
        for preset in [1, 3, 6, 9]:
            try:
                lzma_pts.append((preset, len(lzma.compress(data, preset=preset)) / orig))
            except Exception:
                pass

        fig, ax = plt.subplots(figsize=(4.2, 2.0))
        fig.patch.set_facecolor(BG)
        _style_ax(ax)

        ax.plot(levels, zlib_r, color=GREEN,  linewidth=1.4, label='zlib',  marker='o', markersize=2.5)
        ax.plot(levels, bz2_r,  color=YELLOW, linewidth=1.4, label='bz2',   marker='o', markersize=2.5)
        if lzma_pts:
            lx, ly = zip(*lzma_pts)
            ax.plot(lx, ly, color=ORANGE, linewidth=1.4, label='lzma', marker='o', markersize=2.5)

        ax.axhline(0.95, color=RED, linewidth=0.6, linestyle='--', alpha=0.45, label='0.95 (incompressible)')
        ax.axhline(1.0,  color='#30363d', linewidth=0.5)
        ax.set_xlim(1, 9)
        ax.set_ylim(0, 1.15)
        ax.set_xlabel('Compression level', color=MUTED, fontsize=7)
        ax.set_ylabel('Ratio (compressed / original)', color=MUTED, fontsize=7)
        ax.legend(fontsize=5.5, facecolor='#161b22', edgecolor='#30363d',
                  labelcolor=MUTED, loc='upper right')

        plt.tight_layout(pad=0.4)
        b64 = _save_fig(fig)
        plt.close(fig)
        return {"ok": True, "b64": b64}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def bigram_matrix_chart(data: bytes, file_mode: str = "binary") -> Dict[str, Any]:
    """
    Binary mode : 256×256 full-byte bigram matrix.
    Text mode   : 95×95 matrix restricted to printable ASCII (0x20–0x7E).
    """
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
        from matplotlib.colors import LinearSegmentedColormap

        data = data[:_MAX_BYTES]

        if file_mode == "text":
            # Filter to printable ASCII and remap to 0–94
            arr_full = np.frombuffer(data, dtype=np.uint8)
            arr = arr_full[(arr_full >= _ASCII_LO) & (arr_full <= _ASCII_HI)].astype(np.int32) - _ASCII_LO
            if len(arr) < 2:
                return {"ok": False, "error": "file too small after ASCII filter"}
            n = _ASCII_N
            matrix = np.zeros((n, n), dtype=np.float64)
            np.add.at(matrix, (arr[:-1], arr[1:]), 1)
            xlabel = f'Char n+1 (0x{_ASCII_LO:02X}–0x{_ASCII_HI:02X})'
            ylabel = f'Char n  (0x{_ASCII_LO:02X}–0x{_ASCII_HI:02X})'
            # Annotation lines for a few notable ASCII positions (relative to _ASCII_LO)
            markers = [(ord('A') - _ASCII_LO, 'A'), (ord('a') - _ASCII_LO, 'a'),
                       (ord('0') - _ASCII_LO, '0')]
        else:
            if len(data) < 2:
                return {"ok": False, "error": "file too small"}
            arr = np.frombuffer(data, dtype=np.uint8)
            n = 256
            matrix = np.zeros((n, n), dtype=np.float64)
            np.add.at(matrix, (arr[:-1], arr[1:]), 1)
            xlabel = 'Byte n+1'
            ylabel = 'Byte n'
            markers = [(0x20, 'space'), (0x41, 'A'), (0x00, 'NUL')]

        total = matrix.sum()
        if total > 0:
            matrix /= total
        matrix = np.log1p(matrix * 1e6)

        cmap = LinearSegmentedColormap.from_list(
            'mh', [BG, '#0d3b5e', '#1a6e5e', GREEN, YELLOW], N=256
        )
        fig, ax = plt.subplots(figsize=(2.8, 2.8))
        fig.patch.set_facecolor(BG)
        _style_ax(ax)
        ax.imshow(matrix, cmap=cmap, aspect='auto', origin='upper', interpolation='nearest')
        ax.set_xlabel(xlabel, color=MUTED, fontsize=7)
        ax.set_ylabel(ylabel, color=MUTED, fontsize=7)
        for val, _ in markers:
            ax.axvline(val, color='#30363d', linewidth=0.4, alpha=0.6)
            ax.axhline(val, color='#30363d', linewidth=0.4, alpha=0.6)

        plt.tight_layout(pad=0.4)
        b64 = _save_fig(fig)
        plt.close(fig)
        return {"ok": True, "b64": b64}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# Cluster palette — distinct colours for up to 12 clusters; noise is MUTED
_CLUSTER_PALETTE = [
    '#2ad67c',  # 0 green
    '#4ea8e8',  # 1 blue
    '#f0c64a',  # 2 yellow
    '#e87c4e',  # 3 orange
    '#b77be8',  # 4 purple
    '#e84e8a',  # 5 pink
    '#4ee8d6',  # 6 cyan
    '#e8e84e',  # 7 lime
    '#e84e4e',  # 8 red
    '#7c4ee8',  # 9 violet
    '#4e8ae8',  # 10 steel blue
    '#e8a84e',  # 11 amber
]


def takens_embedding_chart(data: bytes, file_mode: str = "binary") -> Dict[str, Any]:
    """
    Byte trigram (3-gram) scatter plot projected to 2-D via PCA.
    Points are coloured by HDBSCAN density cluster; noise points (-1) are grey.
    HDBSCAN adapts to variable local density — no epsilon parameter needed.
    Text mode filters to printable ASCII (0x20–0x7E) before all computations.
    """
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
        from sklearn.cluster import HDBSCAN

        data = data[:_MAX_BYTES]

        arr_full = np.frombuffer(data, dtype=np.uint8).astype(np.float64)

        if file_mode == "text":
            arr = arr_full[(arr_full >= _ASCII_LO) & (arr_full <= _ASCII_HI)]
            if len(arr) < 3:
                return {"ok": False, "error": "file too small after ASCII filter"}
        else:
            arr = arr_full
            if len(arr) < 3:
                return {"ok": False, "error": "file too small"}

        # Build trigram matrix in 3-D byte space
        X = np.column_stack([arr[:-2], arr[1:-1], arr[2:]])
        rng = np.random.default_rng(42)
        if len(X) > 8000:
            idx = rng.choice(len(X), 8000, replace=False)
            X = X[idx]

        # ── HDBSCAN clustering in the raw 3-D byte space ─────────────────────
        # min_cluster_size ≈ 0.5 % of points (at least 5); no epsilon needed —
        # HDBSCAN adapts to local density variations across the byte cloud.
        min_cluster_size = max(5, len(X) // 200)
        labels = HDBSCAN(min_cluster_size=min_cluster_size, copy=True).fit_predict(X)

        n_clusters = int(labels.max()) + 1  # -1 is noise, not counted

        # Map cluster label → RGB colour (list of floats in [0,1] for matplotlib)
        def _hex_to_rgb01(h: str):
            h = h.lstrip('#')
            return [int(h[i:i+2], 16) / 255.0 for i in (0, 2, 4)]

        noise_rgb = _hex_to_rgb01(MUTED)
        palette   = [_hex_to_rgb01(_CLUSTER_PALETTE[i % len(_CLUSTER_PALETTE)])
                     for i in range(max(n_clusters, 1))]

        point_colors = np.array([
            noise_rgb if lbl == -1 else palette[lbl % len(palette)]
            for lbl in labels
        ], dtype=np.float32)

        # ── PCA 2-D projection ───────────────────────────────────────────────
        Xc  = X - X.mean(axis=0)
        cov = np.cov(Xc.T)
        _, eigenvectors = np.linalg.eigh(cov)
        pc   = eigenvectors[:, -2:]
        proj = Xc @ pc

        # ── 2-D scatter (cluster-coloured PNG) ───────────────────────────────
        fig, ax = plt.subplots(figsize=(3.0, 3.0))
        fig.patch.set_facecolor(BG)
        _style_ax(ax)

        # Draw noise first (grey, more transparent) then clusters on top
        noise_mask = labels == -1
        if noise_mask.any():
            ax.scatter(proj[noise_mask, 0], proj[noise_mask, 1],
                       c=[noise_rgb], s=0.6, alpha=0.25, linewidths=0)

        for cid in range(n_clusters):
            mask = labels == cid
            if not mask.any():
                continue
            rgb = palette[cid % len(palette)]
            ax.scatter(proj[mask, 0], proj[mask, 1],
                       c=[rgb], s=1.0, alpha=0.7, linewidths=0,
                       label=f'C{cid}')

        ax.set_xlabel('PC 1', color=MUTED, fontsize=7)
        ax.set_ylabel('PC 2', color=MUTED, fontsize=7)
        ax.set_xticks([])
        ax.set_yticks([])

        # Compact cluster legend (only when there are clusters and they fit)
        if 1 <= n_clusters <= 12:
            ax.legend(fontsize=5, facecolor='#161b22', edgecolor='#30363d',
                      labelcolor=MUTED, loc='best', markerscale=2,
                      framealpha=0.6, ncol=min(n_clusters, 4))

        plt.tight_layout(pad=0.4)
        b64 = _save_fig(fig)
        plt.close(fig)

        # ── 3-D point cloud data for the WebGL view ──────────────────────────
        # c3d carries cluster index (integer); -1 = noise
        # The WebGL shader now receives discrete labels, not a gradient [0,1]
        x3d  = X[:, 0].astype(int).tolist()
        y3d  = X[:, 1].astype(int).tolist()
        z3d  = X[:, 2].astype(int).tolist()
        c3d  = labels.tolist()                      # int: -1 … n_clusters-1
        # Pre-bake RGB for the WebGL renderer so it needs no palette logic
        rgb3d = [[round(r, 4), round(g, 4), round(b, 4)]
                 for r, g, b in point_colors.tolist()]

        return {
            "ok": True,
            "b64": b64,
            "hdbscan": {"n_clusters": n_clusters, "min_cluster_size": min_cluster_size},
            "points3d": {"x": x3d, "y": y3d, "z": z3d, "c": c3d, "rgb": rgb3d},
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ---------------------------------------------------------------------------
# LLM image interpretation
# ---------------------------------------------------------------------------

def _interpret_image(b64: str, chart_label: str, file_mode: str, model: str, cb: Callable) -> str:
    """Send the chart image to the LLM with mode-aware context and return a 1–3 sentence interpretation."""
    try:
        from agent.llm_factory import get_llm
        from langchain_core.messages import HumanMessage, SystemMessage

        if not model:
            return ""

        mode_contexts = _CHART_CONTEXTS.get(file_mode, _CHART_CONTEXTS["binary"])
        context = mode_contexts.get(chart_label, "")

        file_type_note = (
            "This is an interpreted/text-based file (script or markup). "
            "The byte distributions reflect ASCII character frequencies, NOT binary executable structure. "
            "Normal benign scripts have entropy of 4–5 bits/byte and structured character clusters. "
            "Obfuscation, base64 blobs, or random identifier names will stand out as anomalies."
            if file_mode == "text" else
            "This is a binary executable or binary file format."
        )

        system_text = (
            "You are a malware analyst interpreting static byte-level visualizations. "
            f"{file_type_note} "
            "Give a direct, concrete observation about what you see in THIS specific image — "
            "1 to 3 sentences maximum. Do not explain the theory or method. "
            "Just describe the visible pattern and what it suggests about this specific file."
        )
        user_text = (
            f"Chart: {chart_label}\n\n"
            f"Interpretation guide (do NOT repeat this in your answer):\n{context}\n\n"
            "Describe in 1–3 sentences only what you observe and what it suggests about this file."
        )

        cb(f"Interpreting {chart_label} [{file_mode}] ({len(b64):,} bytes image)")
        llm = get_llm(model)
        message = HumanMessage(content=[
            {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{b64}"}},
            {"type": "text", "text": user_text},
        ])
        resp = llm.invoke([SystemMessage(content=system_text), message])

        raw = resp.content
        if isinstance(raw, str):
            return raw.strip()
        if isinstance(raw, list):
            for part in raw:
                if isinstance(part, dict) and part.get("type") == "text":
                    return part.get("text", "").strip()
                if isinstance(part, str):
                    return part.strip()
        return ""
    except Exception as e:
        cb(f"Interpretation failed for {chart_label}: {e}")
        return ""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _detect_file_mode(data: bytes) -> str:
    """
    Detect whether data is text-like or binary from its byte distribution.
    Samples the first 8 KB: if ≥80 % of bytes are printable ASCII or common
    whitespace (tab/LF/CR), the file is treated as text.
    """
    if not data:
        return "binary"
    sample = data[:8192]
    printable = sum(1 for b in sample if b in (0x09, 0x0A, 0x0D) or 0x20 <= b <= 0x7E)
    return "text" if (printable / len(sample)) >= 0.80 else "binary"


def compute_all(
    sample_path: str,
    model: str = "",
    file_mode: str = "auto",
    progress_cb: Optional[Callable] = None,
) -> Dict[str, Any]:
    cb = progress_cb or (lambda msg: None)

    try:
        with open(sample_path, 'rb') as f:
            data = f.read()
    except Exception as e:
        return {"error": str(e)}

    if file_mode == "auto":
        file_mode = _detect_file_mode(data)

    charts = [
        ("entropy_profile",   "entropy profile",           entropy_profile_chart),
        ("compression_curve", "compression curve",          compression_curve_chart),
        ("bigram_matrix",     "byte bigram matrix",         bigram_matrix_chart),
        ("takens_embedding",  "byte trigram scatter (PCA)", takens_embedding_chart),
    ]

    result: Dict[str, Any] = {"file_mode": file_mode}
    for key, label, fn in charts:
        cb(f"Computing {label} [{file_mode}]")
        chart = fn(data, file_mode)
        if chart.get("ok") and model:
            chart["interpretation"] = _interpret_image(chart["b64"], label, file_mode, model, cb)
        # Store the plain-text context so the template can display it
        mode_contexts = _CHART_CONTEXTS.get(file_mode, _CHART_CONTEXTS["binary"])
        chart["interp_hint"] = mode_contexts.get(label, "")
        result[key] = chart

    return result
