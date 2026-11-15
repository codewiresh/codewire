#!/usr/bin/env python3
"""Render a recorded terminal transcript as an animated SVG.

The transcript is JSON lines from scripts/docs/record-readme-walkthrough.sh:
{"t": seconds, "cmd": "..."} for a command typed at the prompt and
{"t": seconds, "out": "..."} for each line it printed. Lines appear at their
recorded times, compressed so that slow steps don't stall the recording; the
window scrolls as a terminal does, holds the last screen for a few seconds and
starts again. With reduced motion the last screen shows at once.
"""

import argparse
import json
import re
import sys
from xml.sax.saxutils import escape

# Terminal escapes, then the control characters XML 1.0 forbids; a tab stays.
ESCAPE_SEQUENCE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

COLUMNS = 92
ROWS = 22
FONT_SIZE = 14
LINE_HEIGHT = 20
CHAR_WIDTH = 8.43  # a 14px monospace advance
PAD = 16
TITLE_BAR = 32

TYPE_DELAY = 0.6  # before a command appears
FIRST_OUTPUT = 0.3  # from a command to its first line
MAX_STEP_WAIT = 2.0  # longest real wait shown between two lines
LINE_GAP = 0.04
STEP_GAP = 0.9  # after a step's last line
HOLD = 3.0  # on the last screen, before the recording starts again


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("transcript")
    parser.add_argument("output")
    parser.add_argument("--title", default="")
    parser.add_argument(
        "--replace",
        action="append",
        default=[],
        metavar="OLD=NEW",
        help="replace text in every line, such as a server-specific domain",
    )
    return parser.parse_args()


def load(path: str, replacements: list[tuple[str, str]]) -> list[dict]:
    events = []
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            event = json.loads(raw)
            text = event.get("cmd", event.get("out", ""))
            text = CONTROL.sub("", ESCAPE_SEQUENCE.sub("", text))
            for old, new in replacements:
                text = text.replace(old, new)
            # A progress line that a terminal redraws as its finished line.
            if "out" in event and text.lstrip().startswith("◐"):
                continue
            events.append({"t": event["t"], "cmd": "cmd" in event, "text": text})
    return events


def wrap(text: str) -> list[str]:
    if not text:
        return [""]
    return [text[i:i + COLUMNS] for i in range(0, len(text), COLUMNS)]


def timeline(events: list[dict]) -> list[tuple[float, bool, str]]:
    """Each screen line with the second it appears and whether it is a command."""
    lines: list[tuple[float, bool, str]] = []
    clock = 0.0
    last_real = None
    for event in events:
        if event["cmd"]:
            clock += TYPE_DELAY if not lines else STEP_GAP
            moment = clock
            clock += FIRST_OUTPUT
        else:
            waited = 0.0 if last_real is None else event["t"] - last_real
            clock += min(max(waited, 0.0), MAX_STEP_WAIT) + LINE_GAP
            moment = clock
        last_real = event["t"]
        for i, piece in enumerate(wrap(event["text"])):
            lines.append((moment, event["cmd"] and i == 0, piece))
    return lines


def render(lines: list[tuple[float, bool, str]], title: str) -> str:
    width = round(PAD * 2 + COLUMNS * CHAR_WIDTH)
    height = TITLE_BAR + PAD * 2 + ROWS * LINE_HEIGHT
    total = lines[-1][0] + HOLD

    # The window scrolls by one line each time a line lands below the last row.
    scroll_frames = [(0.0, 0)]
    for index, (moment, _, _) in enumerate(lines):
        offset = max(0, index + 1 - ROWS) * LINE_HEIGHT
        if offset != scroll_frames[-1][1]:
            scroll_frames.append((moment, offset))
    final_offset = scroll_frames[-1][1]
    keyframes = "".join(
        f"{moment / total * 100:.3f}%{{transform:translateY(-{offset}px)}}"
        for moment, offset in scroll_frames
    ) + f"100%{{transform:translateY(-{final_offset}px)}}"

    # Each line has its own keyframes, so every animation shares one period
    # and the whole recording loops together.
    reveal_rules = []
    text_rows = []
    for index, (moment, is_command, piece) in enumerate(lines):
        reveal_rules.append(
            f"@keyframes a{index}{{0%{{opacity:0}}{moment / total * 100:.3f}%{{opacity:1}}100%{{opacity:1}}}}"
            f".l{index}{{animation:a{index} {total:.2f}s step-end infinite}}"
        )
        y = index * LINE_HEIGHT + FONT_SIZE
        body = escape(piece)
        if is_command:
            body = f'<tspan class="p">$ </tspan><tspan class="c">{body}</tspan>'
        else:
            body = f'<tspan class="o">{body}</tspan>'
        text_rows.append(
            f'<text class="l l{index}" x="0" y="{y}">{body}</text>'
        )

    style = f"""
.bg{{fill:#0d1117}} .bar{{fill:#161b22}} .t{{fill:#8b949e;font:12px ui-sans-serif,system-ui,sans-serif}}
text{{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;font-size:{FONT_SIZE}px;white-space:pre}}
.p{{fill:#7ee787}} .c{{fill:#f0f6fc;font-weight:600}} .o{{fill:#c9d1d9}}
.l{{opacity:0}}
{"".join(reveal_rules)}
.s{{animation:scroll {total:.2f}s step-end infinite}}
@keyframes scroll{{{keyframes}}}
@media (prefers-reduced-motion:reduce){{.l{{animation:none;opacity:1}}.s{{animation:none;transform:translateY(-{final_offset}px)}}}}
"""
    dots = "".join(
        f'<circle cx="{PAD + i * 18}" cy="{TITLE_BAR / 2}" r="5.5" fill="{color}"/>'
        for i, color in enumerate(("#ff5f57", "#febc2e", "#28c840"))
    )
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="{escape(title)}">
<title>{escape(title)}</title>
<style>{style}</style>
<rect class="bg" width="{width}" height="{height}" rx="8"/>
<path class="bar" d="M8 0H{width - 8}A8 8 0 0 1 {width} 8V{TITLE_BAR}H0V8A8 8 0 0 1 8 0Z"/>
{dots}
<text class="t" x="{width / 2}" y="{TITLE_BAR / 2 + 4}" text-anchor="middle">{escape(title)}</text>
<svg x="{PAD}" y="{TITLE_BAR + PAD}" width="{width - PAD * 2}" height="{ROWS * LINE_HEIGHT}">
<g class="s" xml:space="preserve">
{chr(10).join(text_rows)}
</g>
</svg>
</svg>
"""


def main() -> int:
    args = parse_args()
    replacements = []
    for item in args.replace:
        old, sep, new = item.partition("=")
        if not sep or not old:
            print(f"--replace needs OLD=NEW, got {item!r}", file=sys.stderr)
            return 2
        replacements.append((old, new))
    lines = timeline(load(args.transcript, replacements))
    if not lines:
        print("the transcript is empty", file=sys.stderr)
        return 1
    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write(render(lines, args.title))
    return 0


if __name__ == "__main__":
    sys.exit(main())
