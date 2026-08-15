#!/usr/bin/env python3
"""Pretty-print a hunt report (Markdown) to a terminal.

Written for the Suricata hunting skills: a hunt report is delivered locally and read
in a terminal, so it needs to render there without a Markdown viewer installed.

    python3 mdpretty.py report.md              # colour when stdout is a TTY
    python3 mdpretty.py --no-color report.md   # force plain text
    COLUMNS=140 python3 mdpretty.py report.md  # override width

Design notes:
  * Style is tracked per character, so word-wrapping can never split a bold or code
    span across an escape sequence — the failure mode of naive regex renderers.
  * Colour is disabled automatically when stdout is not a TTY, so redirecting to a
    file or a pager yields clean plain text with no escape codes.
  * A table with too many columns to stay legible is rendered as one labelled block
    per row instead of a squeezed grid. The hunt skills forbid truncating
    dns.rrname / dns.rdata, and a narrow grid cannot honour that.

Supported: ATX headings, tables, ordered/unordered lists, task-list checkboxes,
fenced code blocks, block quotes, horizontal rules, and inline **bold**, *italic*,
`code`, [links](url). Everything else passes through as text.
"""
import argparse, html, os, re, shutil, sys

MAX_WIDTH = 118
WIDE_TABLE_COLS = 6          # at or above this column count, consider record mode
MIN_COL = 8                  # a grid column is never squeezed below this

# ANSI palette; blanked by --no-color or a non-TTY stdout.
R = B = D = I = U = CY = YE = GR = MA = BL = GY = ''


def set_palette(colour):
    global R, B, D, I, U, CY, YE, GR, MA, BL, GY
    if colour:
        R, B, D, I, U = '\033[0m', '\033[1m', '\033[2m', '\033[3m', '\033[4m'
        CY, YE, GR = '\033[36m', '\033[33m', '\033[32m'
        MA, BL, GY = '\033[35m', '\033[34m', '\033[90m'
    else:
        R = B = D = I = U = CY = YE = GR = MA = BL = GY = ''


def unescape(t):
    """Markdown/HTML escapes that would otherwise print literally in a cell."""
    t = t.replace('&nbsp;', ' ')
    t = html.unescape(t)
    return re.sub(r'\\([|*_`\[\]])', r'\1', t)


def _style(bold, ital, code):
    s = ''
    if code: s += GR
    if bold: s += B
    if ital: s += I
    return s


def runs(md):
    """Markdown string -> [(char, ansi_style)], markers consumed.

    Working per character is what lets wrap_runs() break anywhere safely.
    """
    md = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'\1 (\2)', md)
    out, i, n = [], 0, len(md)
    bold = ital = code = False
    while i < n:
        if md[i] == '\\' and i + 1 < n and md[i + 1] in '|*_`[]':
            out.append((md[i + 1], _style(bold, ital, code))); i += 2; continue
        if md.startswith('**', i) and not code:
            bold = not bold; i += 2; continue
        if md[i] == '`':
            code = not code; i += 1; continue
        if md[i] == '*' and not code:
            ital = not ital; i += 1; continue
        out.append((md[i], _style(bold, ital, code))); i += 1
    return out


def render(rs):
    """[(char, style)] -> string, emitting an escape only when the style changes."""
    out, cur = [], ''
    for ch, st in rs:
        if st != cur:
            if cur: out.append(R)
            out.append(st); cur = st
        out.append(ch)
    if cur: out.append(R)
    return ''.join(out)


def wrap_runs(rs, width):
    """Word-wrap a run list -> list of run lists. Over-long tokens are hard-broken."""
    width = max(width, 4)
    words, word = [], []
    for ch, st in rs:
        if ch == ' ':
            if word: words.append(word); word = []
            words.append((' ', st))          # a space keeps its own style
        else:
            word.append((ch, st))
    if word: words.append(word)

    lines, cur = [], []
    def flush():
        while cur and cur[-1][0] == ' ': cur.pop()
        lines.append(list(cur)); cur.clear()

    for tok in words:
        if isinstance(tok, tuple):           # space
            if cur: cur.append(tok)
            continue
        if len(tok) > width:                 # e.g. a 200-char base64 rdata
            while tok:
                room = width - len(cur)
                if room <= 0:
                    flush(); room = width
                cur += tok[:room]; tok = tok[room:]
            continue
        if len(cur) + len(tok) > width:
            flush()
        cur += tok
    flush()
    return lines or [[]]


def split_cells(line):
    line = line.strip()
    if line.startswith('|'): line = line[1:]
    if line.endswith('|'):   line = line[:-1]
    return [c.strip() for c in re.split(r'(?<!\\)\|', line)]


def plain(t):
    return re.sub(r'\s+', ' ', re.sub(r'\*\*|`', '', unescape(t))).strip()


def emit_records(hdr, body, width):
    """Wide table -> one labelled block per row. Values are never truncated."""
    labels = [plain(h) for h in hdr]
    lw = max(len(l) for l in labels)
    for k, row in enumerate(body, 1):
        first = plain(row[0]) if row else ''
        title = ' %s ' % first if 0 < len(first) <= 40 else ' row %d ' % k
        print()
        print(GY + '\u2576' + title.center(min(width - 2, max(24, len(title) + 10)), '\u2500')
              + '\u2574' + R)
        for i, lab in enumerate(labels):
            val = row[i].strip() if i < len(row) else ''
            if not val: continue
            lines = wrap_runs(runs(unescape(val)), width - lw - 6)
            print('  ' + D + CY + lab.ljust(lw) + R + GY + ' : ' + R + render(lines[0]))
            for l in lines[1:]:
                print('  ' + ' ' * lw + '   ' + render(l))


def emit_table(rows, width):
    hdr, body = rows[0], rows[1:]
    n = len(hdr)
    body = [r[:n] + [''] * (n - len(r)) for r in body]
    cells = [[runs(unescape(c)) for c in r] for r in [hdr] + body]
    natural = [max(len(r[i]) for r in cells) for i in range(n)]
    avail = width - (3 * n + 1)

    if n >= WIDE_TABLE_COLS and sum(natural) > avail:
        emit_records(hdr, body, width); return

    wid = natural[:]
    while sum(wid) > avail and max(wid) > MIN_COL:
        wid[max(range(n), key=lambda i: wid[i])] -= 1

    bar = lambda l, m, r: GY + l + m.join('\u2500' * (w + 2) for w in wid) + r + R

    def row(cellruns, extra=''):
        cols = [wrap_runs(cellruns[i], wid[i]) for i in range(n)]
        for k in range(max(len(c) for c in cols)):
            parts = []
            for i in range(n):
                seg = cols[i][k] if k < len(cols[i]) else []
                if extra: seg = [(c, extra + s) for c, s in seg]
                parts.append(render(seg) + ' ' * (wid[i] - len(seg)))
            print(GY + '\u2502 ' + R + (GY + ' \u2502 ' + R).join(parts) + GY + ' \u2502' + R)

    print(bar('\u250c', '\u252c', '\u2510'))
    row(cells[0], B + CY)
    print(bar('\u251c', '\u253c', '\u2524'))
    for c in cells[1:]:
        row(c)
    print(bar('\u2514', '\u2534', '\u2518'))


BREAK = r'^\s*[|#`>]|^\s*([-*+]|\d+[.)])\s+|^\s*[-*_]{3,}\s*$'


def emit_quote(lines, width):
    """Block quote: keeps its own headings, wraps its paragraphs, draws a left rule.

    Warning callouts in hunt READMEs are written as block quotes with a heading
    inside, so a naive one-line-per-source-line quote renders them unreadably.
    """
    rule = GY + '  \u2503 ' + R
    inner = width - 4
    print()
    buf = []

    def flush():
        if not buf: return
        for ln in wrap_runs(runs(unescape(' '.join(buf))), inner):
            print(rule + render(ln))
        buf.clear()

    for raw in lines:
        m = re.match(r'^(#{1,6})\s+(.*)$', raw.strip())
        if m:
            flush()
            print(rule + B + YE + plain(m.group(2)) + R)
            continue
        if not raw.strip():
            flush(); print(rule.rstrip()); continue
        lm = re.match(r'^(\s*)([-*+]|\d+[.)])\s+(.*)$', raw)
        if lm:
            flush()
            bullet = BL + ('\u2022' if lm.group(2) in '-*+' else lm.group(2)) + R
            ls = wrap_runs(runs(unescape(lm.group(3))), inner - 2)
            print(rule + bullet + ' ' + render(ls[0]))
            for l in ls[1:]:
                print(rule + '  ' + render(l))
            continue
        buf.append(raw.strip())
    flush()
    print()


def render_file(path, width):
    src = open(path, encoding='utf-8').read().split('\n')
    i, n = 0, len(src)
    while i < n:
        line = src[i]

        if line.startswith('```'):
            i += 1
            while i < n and not src[i].startswith('```'):
                print('  ' + GY + '\u2502 ' + R + GR + src[i] + R); i += 1
            i += 1; continue

        if not line.strip():
            print(); i += 1; continue

        if re.fullmatch(r'\s*[-*_]{3,}\s*', line):
            print(GY + '\u2500' * width + R); i += 1; continue

        m = re.match(r'^(#{1,6})\s+(.*)$', line)
        if m:
            lvl, txt = len(m.group(1)), plain(m.group(2))
            print()
            if lvl == 1:
                print(B + MA + '\u2501' * width + R)
                print(B + MA + txt.center(width) + R)
                print(B + MA + '\u2501' * width + R)
            elif lvl == 2:
                print(B + YE + '\u2590 ' + txt + R)
                print(YE + '\u2500' * min(width, len(txt) + 2) + R)
            else:
                print(B + CY + '  ' + txt + R)
            i += 1; continue

        if line.lstrip().startswith('|'):
            rows = []
            while i < n and src[i].lstrip().startswith('|'):
                c = split_cells(src[i])
                if not all(re.fullmatch(r':?-{2,}:?', x) for x in c if x):
                    rows.append(c)
                i += 1
            if rows:
                print(); emit_table(rows, width)
            continue

        m = re.match(r'^(\s*)([-*+]|\d+[.)])\s+(.*)$', line)
        if m:
            ind, mark, txt = m.groups()
            j = i + 1
            while j < n and src[j].strip() and not re.match(BREAK, src[j]):
                txt += ' ' + src[j].strip(); j += 1
            box = re.match(r'^\[([ xX])\]\s*(.*)$', txt)
            if box:
                bullet = (GR + '\u2714' + R) if box.group(1).lower() == 'x' else (GY + '\u2610' + R)
                txt = box.group(2)
                marklen = 1
            else:
                bullet = BL + ('\u2022' if mark in '-*+' else mark) + R
                marklen = 1 if mark in '-*+' else len(mark)
            pad = ' ' * (len(ind) + marklen + 1)
            ls = wrap_runs(runs(unescape(txt)), width - len(pad))
            print(ind + bullet + ' ' + render(ls[0]))
            for l in ls[1:]:
                print(pad + render(l))
            i = j; continue

        if line.lstrip().startswith('>'):
            quoted = []
            while i < n and (src[i].lstrip().startswith('>') or
                             (quoted and not src[i].strip() and
                              i + 1 < n and src[i + 1].lstrip().startswith('>'))):
                quoted.append(re.sub(r'^\s*>\s?', '', src[i])); i += 1
            emit_quote(quoted, width); continue

        buf, j = [line], i + 1
        while j < n and src[j].strip() and not re.match(BREAK, src[j]):
            buf.append(src[j]); j += 1
        for ln in wrap_runs(runs(unescape(' '.join(x.strip() for x in buf))), width):
            print(render(ln))
        i = j


def main(argv=None):
    ap = argparse.ArgumentParser(description='Pretty-print a Markdown hunt report to a terminal.')
    ap.add_argument('report', help='path to the .md report')
    ap.add_argument('--no-color', action='store_true', help='force plain text (no ANSI)')
    ap.add_argument('--width', type=int, default=None, help='output width (default: terminal, capped at %d)' % MAX_WIDTH)
    a = ap.parse_args(argv)

    set_palette(not a.no_color and sys.stdout.isatty())
    width = a.width or min(int(os.environ.get('COLUMNS') or
                               shutil.get_terminal_size((100, 40)).columns), MAX_WIDTH)
    render_file(a.report, max(width, 40))


if __name__ == '__main__':
    main()
