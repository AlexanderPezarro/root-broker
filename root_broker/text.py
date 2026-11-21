"""Making agent-controlled text safe to show to the approver."""
import html


def visible(s):
    """Plain-text form of agent-controlled text: non-ASCII and control characters (bidi overrides,
    homoglyphs, terminal escapes) become \\uXXXX so they can't disguise the command."""
    return "".join(ch if ch == "\n" or " " <= ch <= "~" else f"\\u{ord(ch):04x}" for ch in str(s))


def show(s):
    """HTML-escape agent-controlled text, with the characters visible() rewrites highlighted."""
    out = []
    for ch in str(s):
        if ch == "\n" or " " <= ch <= "~":
            out.append(html.escape(ch))
        else:
            out.append(f'<mark>\\u{ord(ch):04x}</mark>')
    return "".join(out)
