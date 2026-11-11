from .shared import *
from .mesh import sanitize_rust_source

from dataclasses import dataclass
from fnmatch import fnmatchcase
from html.parser import HTMLParser


# ---------------------------------------------------------------------------
# Design-system token, ownership, and markup guard


DESIGN_POLICY_REL = "scripts/checks/contracts/design-token-policy.json"
DESIGN_PACKAGE = "packages/codewire-design"
DESIGN_FIXTURES = f"{DESIGN_PACKAGE}/reference/fixtures"
DESIGN_TEMPLATES = "crates/codewire-dashboard-web/templates"
DESIGN_RUST_ROUTES = "crates/codewire-dashboard-web/src/routes"
DESIGN_STYLESHEET_PATTERNS = (
    f"{DESIGN_PACKAGE}/styles.css",
    f"{DESIGN_PACKAGE}/components.css",
    f"{DESIGN_PACKAGE}/routes/*.css",
    f"{DESIGN_FIXTURES}/*.css",
)
DESIGN_MARKUP_PATTERNS = (f"{DESIGN_FIXTURES}/**/*.html", f"{DESIGN_TEMPLATES}/**/*.html")
DESIGN_SCRIPT_FILES = (f"{DESIGN_PACKAGE}/dashboard.js", f"{DESIGN_PACKAGE}/environments.js")
DESIGN_EXCLUDED_PREFIXES = (
    f"{DESIGN_PACKAGE}/reference/source/",
    "crates/codewire-dashboard-web/assets/xterm/",
)
DESIGN_RULES = ("literal", "forbidden", "ownership", "undefined", "markup", "gallery")
DESIGN_POLICY_KEYS = {
    "$comment",
    "schema_version",
    "token_files",
    "isolated_token_files",
    "core_files",
    "gallery_file",
    "breakpoints",
    "literal_properties",
    "ownership_properties",
    "control_classes",
    "js_hook_classes",
}
DESIGN_LITERAL_KINDS = {
    "typography",
    "font",
    "color",
    "border",
    "radius",
    "shadow",
    "spacing",
    "layout_size",
}
DESIGN_OWNERSHIP_KINDS = {"visual", "control_visual", "layout"}
DESIGN_FINGERPRINT_LIMIT = 160
DESIGN_MARKUP_REQUIRED = {
    "select": ("cw-select",),
    "textarea": ("cw-textarea",),
    "input:checkbox": ("cw-checkbox", "cw-switch"),
    "input:radio": ("cw-radio",),
    "details": ("cw-disclosure", "cw-menu"),
}
HTML_VOID_ELEMENTS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr",
}

CSS_WHITESPACE = " \t\r\n\f"
CSS_CLOSERS = {"(": ")", "[": "]", "{": "}"}
CSS_NUMBER = re.compile(r"[+-]?(?:\d+(?:\.\d+)?|\.\d+)(?:[eE][+-]?\d+)?")
CSS_QUOTED = re.compile(r"(\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*')", re.DOTALL)
CSS_EXEMPT_AT_RULES = {"font-face", "keyframes", "-webkit-keyframes"}
CSS_BREAKPOINT_AT_RULES = {"media", "container"}
CSS_SUBJECT_FUNCTIONS = {"is", "matches", "-webkit-any", "-moz-any"}
CSS_MATH_FUNCTIONS = {"calc", "-webkit-calc", "min", "max", "clamp"}
CSS_OPAQUE_FUNCTIONS = {"var", "env", "url", "attr"}
CSS_COLOR_FUNCTIONS = {"rgb", "rgba", "hsl", "hsla", "hwb", "lab", "lch", "oklab", "oklch", "color"}
CSS_ALLOWED_KEYWORDS = {
    "0",
    "auto",
    "none",
    "normal",
    "inherit",
    "initial",
    "unset",
    "revert",
    "revert-layer",
    "currentcolor",
    "transparent",
}
CSS_ALLOWED_UNITS = {
    "fr",
    "vw",
    "vh",
    "vi",
    "vb",
    "dvw",
    "dvh",
    "svw",
    "svh",
    "lvw",
    "lvh",
    "vmin",
    "vmax",
    "dvmin",
    "dvmax",
    "svmin",
    "svmax",
    "lvmin",
    "lvmax",
}
CSS_LENGTH_UNITS = {
    "px",
    "rem",
    "em",
    "ex",
    "rex",
    "ch",
    "rch",
    "cap",
    "rcap",
    "ic",
    "ric",
    "lh",
    "rlh",
    "pt",
    "pc",
    "in",
    "cm",
    "mm",
    "q",
    "cqw",
    "cqh",
    "cqi",
    "cqb",
    "cqmin",
    "cqmax",
}
CSS_HAIRLINE_WIDTHS = {"1px", "2px"}
CSS_BORDER_SHORTHANDS = {
    "border",
    "border-top",
    "border-right",
    "border-bottom",
    "border-left",
    "border-block",
    "border-block-start",
    "border-block-end",
    "border-inline",
    "border-inline-start",
    "border-inline-end",
    "outline",
    "column-rule",
}
CSS_FONT_SIZE_KEYWORDS = {
    "xx-small",
    "x-small",
    "small",
    "medium",
    "large",
    "x-large",
    "xx-large",
    "xxx-large",
    "smaller",
    "larger",
    "math",
}
CSS_NAMED_COLORS = set(
    """
    aliceblue antiquewhite aqua aquamarine azure beige bisque black blanchedalmond blue
    blueviolet brown burlywood cadetblue chartreuse chocolate coral cornflowerblue cornsilk
    crimson cyan darkblue darkcyan darkgoldenrod darkgray darkgreen darkgrey darkkhaki
    darkmagenta darkolivegreen darkorange darkorchid darkred darksalmon darkseagreen
    darkslateblue darkslategray darkslategrey darkturquoise darkviolet deeppink deepskyblue
    dimgray dimgrey dodgerblue firebrick floralwhite forestgreen fuchsia gainsboro ghostwhite
    gold goldenrod gray green greenyellow grey honeydew hotpink indianred indigo ivory khaki
    lavender lavenderblush lawngreen lemonchiffon lightblue lightcoral lightcyan
    lightgoldenrodyellow lightgray lightgreen lightgrey lightpink lightsalmon lightseagreen
    lightskyblue lightslategray lightslategrey lightsteelblue lightyellow lime limegreen linen
    magenta maroon mediumaquamarine mediumblue mediumorchid mediumpurple mediumseagreen
    mediumslateblue mediumspringgreen mediumturquoise mediumvioletred midnightblue mintcream
    mistyrose moccasin navajowhite navy oldlace olive olivedrab orange orangered orchid
    palegoldenrod palegreen paleturquoise palevioletred papayawhip peachpuff peru pink plum
    powderblue purple rebeccapurple red rosybrown royalblue saddlebrown salmon sandybrown
    seagreen seashell sienna silver skyblue slateblue slategray slategrey snow springgreen
    steelblue tan teal thistle tomato turquoise violet wheat white whitesmoke yellow
    yellowgreen accentcolor accentcolortext activetext buttonborder buttonface buttontext
    canvas canvastext field fieldtext graytext highlight highlighttext linktext mark
    marktext selecteditem selecteditemtext visitedtext
    """.split()
)
CSS_REDUCED_MOTION = re.compile(r"prefers-reduced-motion\s*:\s*reduce", re.IGNORECASE)
CSS_VENDOR_PREFIX = re.compile(r"^-(?:webkit|moz|ms|o)-")
ASKAMA_TAG = re.compile(r"\{#.*?#\}|\{%.*?%\}|\{\{.*?\}\}", re.DOTALL)
DYNAMIC_MARKER = "{{}}"
SCRIPT_CLASS = re.compile(r"(?<![A-Za-z0-9_$#-])cw-[A-Za-z0-9_-]+")
SCRIPT_IDENTIFIER = re.compile(r"[A-Za-z0-9_$]+")
SCRIPT_REGEX_PRECEDERS = set("(,=:[!&|?{};+-*%<>~^")
SCRIPT_REGEX_KEYWORDS = {
    "return",
    "typeof",
    "instanceof",
    "in",
    "of",
    "new",
    "delete",
    "void",
    "throw",
    "case",
    "do",
    "else",
    "yield",
    "await",
}
RUST_CLASS_ATTRIBUTE = re.compile(r'class=\\"([^"\\]*)\\"|class="([^"\\]*)"')


def check_design_tokens(args: argparse.Namespace) -> int:
    root = Path(getattr(args, "root", None) or ROOT).resolve()
    corpus: dict[str, str] = {}
    self_test_cases = 0
    try:
        policy = load_design_token_policy(root)
        corpus = design_token_corpus(root)
        violations, failures = design_token_violations(corpus, policy)
        failures = [*failures, *design_token_failures(violations)]
        if not failures and args.self_test:
            self_test_cases = design_tokens_self_test(policy, violations, corpus)
    except Exception as error:  # noqa: BLE001 - repository guard boundary
        failures = [str(error)]

    if failures:
        return report("design tokens", failures)
    print(f"design tokens: OK (no violations in {len(corpus)} design inputs)")
    if self_test_cases:
        print(f"design tokens: self-test OK ({self_test_cases} fixtures)")
    return 0


# ---------------------------------------------------------------------------
# Policy, corpus, and fingerprints


def load_design_token_policy(root: Path) -> dict[str, Any]:
    policy = json.loads((root / DESIGN_POLICY_REL).read_text(encoding="utf-8"))
    if not isinstance(policy, dict) or set(policy) != DESIGN_POLICY_KEYS:
        raise RuntimeError(
            f"design token policy keys must be exactly {stable_json(sorted(DESIGN_POLICY_KEYS))}"
        )
    if policy.get("schema_version") != 1:
        raise RuntimeError("design token policy schema_version must equal 1")
    if not isinstance(policy.get("$comment"), str) or not policy["$comment"].strip():
        raise RuntimeError("design token policy must have a non-empty $comment")
    for key in ("token_files", "isolated_token_files", "core_files", "breakpoints", "control_classes"):
        design_string_list(policy.get(key), f"design token policy {key}", allow_empty=False)
    if not set(policy["isolated_token_files"]) <= set(policy["token_files"]):
        raise RuntimeError("design token policy isolated_token_files must be token files")
    if not isinstance(policy.get("gallery_file"), str) or not policy["gallery_file"].endswith(".html"):
        raise RuntimeError("design token policy gallery_file must be an HTML fixture")
    for breakpoint in policy["breakpoints"]:
        tokens = css_significant(css_tokens(breakpoint))
        if len(tokens) != 1 or tokens[0].kind != "dimension" or tokens[0].unit not in CSS_LENGTH_UNITS:
            raise RuntimeError(f"design token policy breakpoint is not a length: {breakpoint!r}")
    literal = policy.get("literal_properties")
    if not isinstance(literal, dict) or set(literal) != DESIGN_LITERAL_KINDS:
        raise RuntimeError(
            f"design token policy literal_properties must be exactly {stable_json(sorted(DESIGN_LITERAL_KINDS))}"
        )
    ownership = policy.get("ownership_properties")
    if not isinstance(ownership, dict) or set(ownership) != DESIGN_OWNERSHIP_KINDS:
        raise RuntimeError(
            "design token policy ownership_properties must be exactly "
            f"{stable_json(sorted(DESIGN_OWNERSHIP_KINDS))}"
        )
    for table_name, table in (("literal_properties", literal), ("ownership_properties", ownership)):
        for kind, patterns in table.items():
            design_string_list(patterns, f"design token policy {table_name}.{kind}", allow_empty=False)
    for pattern in ownership["layout"]:
        clashes = [
            visual
            for visual in ownership["visual"] + ownership["control_visual"]
            if fnmatchcase(pattern.replace("*", ""), visual) or fnmatchcase(visual.replace("*", ""), pattern)
        ]
        if clashes:
            raise RuntimeError(
                f"design token policy property {pattern!r} is both layout and visual: {stable_json(clashes)}"
            )
    hooks = policy.get("js_hook_classes")
    if not isinstance(hooks, dict) or not all(
        isinstance(name, str) and name.startswith("cw-") and isinstance(reason, str) and reason.strip()
        for name, reason in hooks.items()
    ):
        raise RuntimeError("design token policy js_hook_classes must map cw- classes to reasons")
    return policy


def design_string_list(value: Any, label: str, *, allow_empty: bool) -> None:
    if (
        not isinstance(value, list)
        or (not value and not allow_empty)
        or not all(isinstance(item, str) and item for item in value)
    ):
        raise RuntimeError(f"{label} must be a list of non-empty strings")
    if len(value) != len(set(value)):
        raise RuntimeError(f"{label} contains duplicate values")


def design_token_corpus(root: Path) -> dict[str, str]:
    paths: set[Path] = set()
    for pattern in DESIGN_STYLESHEET_PATTERNS + DESIGN_MARKUP_PATTERNS:
        paths.update(path for path in root.glob(pattern) if path.is_file())
    for rel in DESIGN_SCRIPT_FILES:
        path = root / rel
        if not path.is_file():
            raise RuntimeError(f"design token script input is missing: {rel}")
        paths.add(path)
    paths.update(
        path
        for path in (root / DESIGN_RUST_ROUTES).glob("*.rs")
        if path.is_file() and not path.name.endswith("_tests.rs")
    )
    corpus: dict[str, str] = {}
    for path in sorted(paths):
        rel = path.relative_to(root).as_posix()
        if rel.startswith(DESIGN_EXCLUDED_PREFIXES):
            continue
        corpus[rel] = path.read_text(encoding="utf-8")
    return corpus


def design_fingerprint(rule: str, file: str, context: str, name: str, value: str) -> str:
    return "|".join((rule, file, design_clip(context), name, design_clip(value)))


def design_fingerprint_parts(fingerprint: str) -> tuple[str, str, str]:
    parts = fingerprint.split("|", 2)
    if len(parts) != 3 or parts[0] not in DESIGN_RULES or not parts[1] or parts[2].count("|") < 2:
        raise RuntimeError(f"malformed design token fingerprint: {fingerprint!r}")
    return parts[0], parts[1], parts[2]


def design_clip(text: str) -> str:
    if len(text) <= DESIGN_FINGERPRINT_LIMIT:
        return text
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    return f"{text[:120]}...sha256:{digest}"


def design_token_failures(violations: list[str]) -> list[str]:
    """Every violation fails: the design system has no baseline of exceptions."""
    if not violations:
        return []
    groups: dict[tuple[str, str], list[str]] = {}
    for fingerprint in violations:
        rule, file, detail = design_fingerprint_parts(fingerprint)
        groups.setdefault((file, rule), []).append(detail)
    failures = [f"{len(violations)} violations (selector|property|value); fix each one"]
    for file, rule in sorted(groups):
        details = sorted(groups[(file, rule)])
        failures.append(f"{file} [{rule}]: {len(details)}")
        failures.extend(f"  {detail}" for detail in details)
    return failures


# ---------------------------------------------------------------------------
# CSS tokenizer and parser


@dataclass(frozen=True)
class CssToken:
    kind: str
    value: str = ""
    unit: str = ""
    text: str = ""


@dataclass(frozen=True)
class CssFunction:
    name: str
    args: tuple[Any, ...]


@dataclass(frozen=True)
class CssBlock:
    opener: str
    items: tuple[Any, ...]


@dataclass(frozen=True)
class CssDeclaration:
    name: str
    value: tuple[Any, ...]
    important: bool


@dataclass(frozen=True)
class CssRule:
    at: str | None
    prelude: tuple[Any, ...]
    block: tuple[Any, ...] | None


def css_ident_start(text: str, index: int) -> bool:
    char = text[index] if index < len(text) else ""
    if char == "-":
        following = text[index + 1] if index + 1 < len(text) else ""
        return following in {"-", "_", "\\"} or following.isalpha() or (following != "" and ord(following) > 127)
    return char in {"_", "\\"} or char.isalpha() or (char != "" and ord(char) > 127)


def css_number_start(text: str, index: int) -> bool:
    char = text[index]
    following = text[index + 1] if index + 1 < len(text) else ""
    if char.isdigit():
        return True
    if char == ".":
        return following.isdigit()
    if char in "+-":
        after = text[index + 2] if index + 2 < len(text) else ""
        return following.isdigit() or (following == "." and after.isdigit())
    return False


def css_consume_name(text: str, index: int) -> tuple[str, int]:
    end = index
    while end < len(text):
        char = text[end]
        if char == "\\" and end + 1 < len(text):
            end += 2
        elif char.isalnum() or char in "_-" or ord(char) > 127:
            end += 1
        else:
            break
    return text[index:end], end


def css_tokens(text: str) -> list[CssToken]:
    tokens: list[CssToken] = []
    index = 0
    length = len(text)
    punctuation = {":": "colon", ";": "semicolon", ",": "comma"}
    while index < length:
        char = text[index]
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            index = length if end == -1 else end + 2
            tokens.append(CssToken("ws", text=" "))
        elif char in CSS_WHITESPACE:
            while index < length and text[index] in CSS_WHITESPACE:
                index += 1
            tokens.append(CssToken("ws", text=" "))
        elif char in "\"'":
            end = index + 1
            while end < length and text[end] not in {char, "\n"}:
                end += 2 if text[end] == "\\" else 1
            closed = end < length and text[end] == char
            end = min(end, length)
            tokens.append(CssToken("string", text[index + 1 : end], text=text[index : end + int(closed)]))
            index = end + int(closed)
        elif css_number_start(text, index):
            match = CSS_NUMBER.match(text, index)
            assert match is not None
            end = match.end()
            number = match.group(0)
            if end < length and text[end] == "%":
                tokens.append(CssToken("percentage", number, "%", text[index : end + 1]))
                index = end + 1
            elif css_ident_start(text, end):
                unit, end = css_consume_name(text, end)
                tokens.append(CssToken("dimension", number, unit.lower(), text[index:end]))
                index = end
            else:
                tokens.append(CssToken("number", number, text=number))
                index = end
        elif css_ident_start(text, index):
            name, end = css_consume_name(text, index)
            if end < length and text[end] == "(":
                probe = end + 1
                while probe < length and text[probe] in CSS_WHITESPACE:
                    probe += 1
                if name.lower() == "url" and probe < length and text[probe] not in "\"'":
                    # Unquoted URLs, including data URIs with quotes, colons, and
                    # %23-encoded hex, are one opaque token.
                    close = probe
                    while close < length and text[close] != ")":
                        close += 2 if text[close] == "\\" else 1
                    tokens.append(CssToken("url", text[probe:close].strip(), text=text[index : close + 1]))
                    index = min(close + 1, length)
                else:
                    tokens.append(CssToken("function", name.lower(), text=text[index : end + 1]))
                    index = end + 1
            else:
                tokens.append(CssToken("ident", name, text=name))
                index = end
        elif char == "@" and css_ident_start(text, index + 1):
            name, end = css_consume_name(text, index + 1)
            tokens.append(CssToken("at", name.lower(), text=text[index:end]))
            index = end
        elif char == "#" and index + 1 < length and (
            text[index + 1].isalnum() or text[index + 1] in "_-\\" or ord(text[index + 1]) > 127
        ):
            name, end = css_consume_name(text, index + 1)
            tokens.append(CssToken("hash", name, text=text[index:end]))
            index = end
        else:
            if char in CSS_CLOSERS:
                tokens.append(CssToken("open", char, text=char))
            elif char in ")]}":
                tokens.append(CssToken("close", char, text=char))
            elif char in punctuation:
                tokens.append(CssToken(punctuation[char], char, text=char))
            else:
                tokens.append(CssToken("delim", char, text=char))
            index += 1
    return tokens


def css_component_values(tokens: list[CssToken]) -> list[Any]:
    def consume(index: int, closer: str | None) -> tuple[list[Any], int]:
        items: list[Any] = []
        while index < len(tokens):
            token = tokens[index]
            if token.kind == "close" and token.value == closer:
                return items, index + 1
            if token.kind == "function":
                args, index = consume(index + 1, ")")
                items.append(CssFunction(token.value, tuple(args)))
            elif token.kind == "open":
                inner, index = consume(index + 1, CSS_CLOSERS[token.value])
                items.append(CssBlock(token.value, tuple(inner)))
            else:
                items.append(token)
                index += 1
        return items, index

    return consume(0, None)[0]


def css_is(value: Any, kind: str, text: str | None = None) -> bool:
    return (
        isinstance(value, CssToken)
        and value.kind == kind
        and (text is None or value.value.lower() == text)
    )


def css_significant(values: Any) -> list[Any]:
    return [value for value in values if not css_is(value, "ws")]


def css_strip(values: list[Any]) -> list[Any]:
    start, end = 0, len(values)
    while start < end and css_is(values[start], "ws"):
        start += 1
    while end > start and css_is(values[end - 1], "ws"):
        end -= 1
    return values[start:end]


def css_items(values: list[Any] | tuple[Any, ...], *, declarations: bool) -> list[Any]:
    """Parse a stylesheet or block body into declarations and (nested) rules."""
    items: list[Any] = []
    buffer: list[Any] = []
    values = list(values)
    index = 0

    def flush() -> None:
        if declarations and css_significant(buffer):
            declaration = css_declaration(buffer)
            if declaration is not None:
                items.append(declaration)
        buffer.clear()

    while index < len(values):
        value = values[index]
        index += 1
        if css_is(value, "at") and not css_significant(buffer):
            prelude: list[Any] = []
            block: tuple[Any, ...] | None = None
            while index < len(values):
                current = values[index]
                index += 1
                if css_is(current, "semicolon"):
                    break
                if isinstance(current, CssBlock) and current.opener == "{":
                    block = tuple(css_items(current.items, declarations=True))
                    break
                prelude.append(current)
            items.append(CssRule(value.value, tuple(css_strip(prelude)), block))
            buffer.clear()
        elif css_is(value, "semicolon"):
            flush()
        elif isinstance(value, CssBlock) and value.opener == "{":
            items.append(
                CssRule(None, tuple(css_strip(buffer)), tuple(css_items(value.items, declarations=True)))
            )
            buffer.clear()
        else:
            buffer.append(value)
    flush()
    return items


def css_declaration(buffer: list[Any]) -> CssDeclaration | None:
    values = css_strip(buffer)
    if not values or not css_is(values[0], "ident"):
        return None
    rest = css_strip(values[1:])
    if not rest or not css_is(rest[0], "colon"):
        return None
    value = css_strip(rest[1:])
    important = False
    significant = [position for position, item in enumerate(value) if not css_is(item, "ws")]
    if (
        len(significant) >= 2
        and css_is(value[significant[-1]], "ident", "important")
        and css_is(value[significant[-2]], "delim", "!")
    ):
        important = True
        value = css_strip(value[: significant[-2]])
    name = values[0].value if values[0].value.startswith("--") else values[0].value.lower()
    return CssDeclaration(name, tuple(value), important)


def css_serialize(values: Any, *, selector: bool = False) -> str:
    parts: list[str] = []
    for value in values:
        if isinstance(value, CssFunction):
            parts.append(f"{value.name}({css_serialize(value.args, selector=selector)})")
        elif isinstance(value, CssBlock):
            inner = css_serialize(value.items, selector=selector and value.opener != "[")
            parts.append(f"{value.opener}{inner}{CSS_CLOSERS[value.opener]}")
        elif selector and value.kind == "delim" and value.value in ">+~":
            parts.append(f" {value.value} ")
        else:
            parts.append(value.text)
    return "".join(parts)


def css_normalize(text: str) -> str:
    # Collapse whitespace and comma spacing outside quoted strings only.
    parts = CSS_QUOTED.split(text)
    for index in range(0, len(parts), 2):
        part = re.sub(r"\s+", " ", parts[index])
        part = re.sub(r"\(\s+", "(", part)
        part = re.sub(r"\s+\)", ")", part)
        parts[index] = re.sub(r"\s*,\s*", ", ", part)
    return "".join(parts).strip()


def css_text(values: Any, *, selector: bool = False) -> str:
    return css_normalize(css_serialize(values, selector=selector))


# ---------------------------------------------------------------------------
# Selector analysis


def css_split_commas(values: Any) -> list[list[Any]]:
    parts: list[list[Any]] = [[]]
    for value in values:
        if css_is(value, "comma"):
            parts.append([])
        else:
            parts[-1].append(value)
    return [stripped for stripped in (css_strip(part) for part in parts) if stripped]


def css_last_compound(values: Any) -> list[Any]:
    compounds: list[list[Any]] = [[]]
    for value in values:
        if css_is(value, "ws") or (css_is(value, "delim") and value.value in ">+~"):
            if compounds[-1]:
                compounds.append([])
        else:
            compounds[-1].append(value)
    filled = [compound for compound in compounds if compound]
    return filled[-1] if filled else []


def css_compound_classes(compound: list[Any]) -> set[str]:
    """Classes on the subject compound; :is() expands, :not/:has/:where do not."""
    classes: set[str] = set()
    for index, value in enumerate(compound):
        if css_is(value, "delim", ".") and index + 1 < len(compound) and css_is(compound[index + 1], "ident"):
            classes.add(compound[index + 1].value)
        elif (
            isinstance(value, CssFunction)
            and value.name in CSS_SUBJECT_FUNCTIONS
            and index > 0
            and css_is(compound[index - 1], "colon")
        ):
            for alternative in css_split_commas(value.args):
                classes |= css_compound_classes(css_last_compound(alternative))
    return classes


def css_subject_classes(selector: str) -> set[str]:
    classes: set[str] = set()
    for alternative in css_split_commas(css_component_values(css_tokens(selector))):
        classes |= css_compound_classes(css_last_compound(alternative))
    return classes


def css_selector_classes(values: Any) -> set[str]:
    classes: set[str] = set()
    values = list(values)
    for index, value in enumerate(values):
        if css_is(value, "delim", ".") and index + 1 < len(values) and css_is(values[index + 1], "ident"):
            classes.add(values[index + 1].value)
        elif isinstance(value, CssFunction):
            classes |= css_selector_classes(value.args)
    return classes


# ---------------------------------------------------------------------------
# Value analysis


def css_value_atoms(values: Any, in_math: bool = False):
    for value in values:
        if isinstance(value, CssFunction):
            if value.name in CSS_OPAQUE_FUNCTIONS or value.name in CSS_COLOR_FUNCTIONS:
                yield value, in_math
            else:
                yield from css_value_atoms(value.args, in_math or value.name in CSS_MATH_FUNCTIONS)
        elif isinstance(value, CssBlock):
            yield from css_value_atoms(value.items, in_math)
        elif not css_is(value, "ws"):
            yield value, in_math


def css_functions(values: Any):
    for value in values:
        if isinstance(value, CssFunction):
            yield value
            yield from css_functions(value.args)
        elif isinstance(value, CssBlock):
            yield from css_functions(value.items)


def css_var_names(values: Any) -> set[str]:
    names: set[str] = set()
    for function in css_functions(values):
        if function.name == "var":
            args = css_significant(function.args)
            if args and css_is(args[0], "ident") and args[0].value.startswith("--"):
                names.add(args[0].value)
    return names


def css_has_var_fallback(values: Any) -> bool:
    return any(
        function.name == "var" and any(css_is(arg, "comma") for arg in function.args)
        for function in css_functions(values)
    )


def css_has_data_uri(values: Any) -> bool:
    for value in values:
        if css_is(value, "url") and value.value.lower().startswith("data:"):
            return True
        if isinstance(value, CssFunction):
            if value.name == "url":
                args = css_significant(value.args)
                if args and css_is(args[0], "string") and args[0].value.lower().startswith("data:"):
                    return True
            elif css_has_data_uri(value.args):
                return True
        elif isinstance(value, CssBlock) and css_has_data_uri(value.items):
            return True
    return False


def css_length_key(token: CssToken) -> str:
    number = f"{float(token.value):f}".rstrip("0").rstrip(".")
    return f"{number or '0'}{token.unit}"


def css_color_literal(atom: Any) -> bool:
    if isinstance(atom, CssFunction):
        return atom.name in CSS_COLOR_FUNCTIONS
    if atom.kind == "hash":
        return True
    return atom.kind == "ident" and atom.value.lower() in CSS_NAMED_COLORS


def css_length_literal(token: CssToken, *, allow_width: bool) -> bool:
    if token.unit in CSS_ALLOWED_UNITS or token.unit not in CSS_LENGTH_UNITS:
        return False
    if float(token.value) == 0:
        return False
    return not (allow_width and css_length_key(token) in CSS_HAIRLINE_WIDTHS)


def css_value_literal(values: Any, kind: str, name: str) -> bool:
    allow_width = kind == "border" and (name in CSS_BORDER_SHORTHANDS or name.endswith("-width"))
    for atom, in_math in css_value_atoms(values):
        if css_color_literal(atom):
            return True
        if kind == "color" or not isinstance(atom, CssToken):
            continue
        if atom.kind == "dimension" and css_length_literal(atom, allow_width=allow_width and not in_math):
            return True
        if kind == "typography":
            if atom.kind == "number" and not in_math and float(atom.value) != 0:
                return True
            if atom.kind == "ident" and name == "font-size" and atom.value.lower() in CSS_FONT_SIZE_KEYWORDS:
                return True
    return False


def css_font_parts(values: Any) -> list[list[Any]]:
    """Return the size and optional line-height component of a font shorthand."""
    top = css_significant(values)
    for index, value in enumerate(top):
        if css_is(value, "delim", "/"):
            return [top[index - 1 : index], top[index + 1 : index + 2]]
    for value in top:
        if css_is(value, "comma") or css_is(value, "string"):
            break
        if (
            css_is(value, "dimension")
            or css_is(value, "percentage")
            or (isinstance(value, CssFunction) and value.name in CSS_MATH_FUNCTIONS | {"var"})
            or (css_is(value, "ident") and value.value.lower() in CSS_FONT_SIZE_KEYWORDS)
        ):
            return [[value]]
    return []


def css_custom_literal(values: Any) -> bool:
    for atom, in_math in css_value_atoms(values):
        if isinstance(atom, CssFunction):
            if atom.name in {"var", "env", "attr"}:
                continue
            return True
        if atom.kind in {"string", "hash", "url"}:
            return True
        if atom.kind == "ident" and atom.value.lower() not in CSS_ALLOWED_KEYWORDS:
            return True
        if atom.kind == "number" and not in_math and float(atom.value) != 0:
            return True
        if atom.kind == "dimension" and atom.unit not in CSS_ALLOWED_UNITS and float(atom.value) != 0:
            return True
    return False


def css_outline_removed(values: Any) -> bool:
    atoms = [atom for atom, _ in css_value_atoms(values)]
    return bool(atoms) and all(
        css_is(atom, "ident", "none")
        or ((css_is(atom, "number") or css_is(atom, "dimension")) and float(atom.value) == 0)
        for atom in atoms
    )


def css_prelude_lengths(values: Any) -> list[str]:
    lengths: list[str] = []
    for value in values:
        if css_is(value, "dimension") and value.unit in CSS_LENGTH_UNITS:
            lengths.append(css_length_key(value))
        elif isinstance(value, CssFunction):
            lengths.extend(css_prelude_lengths(value.args))
        elif isinstance(value, CssBlock):
            lengths.extend(css_prelude_lengths(value.items))
    return lengths


# ---------------------------------------------------------------------------
# Markup, script, and Rust HTML class extraction


class DesignMarkupParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: list[tuple[str, list[tuple[str, str | None]], str]] = []
        self.styles: list[str] = []
        self._style: list[str] | None = None
        # Elements whose own content mixes a child element with bare text.
        self.mixed: set[int] = set()
        # Open elements: tag, index in elements, has a child element, has own text.
        self._open: list[list[Any]] = []

    def _child(self, tag: str, attrs: list[tuple[str, str | None]]) -> int:
        if self._open:
            self._open[-1][2] = True
        self.elements.append((tag, attrs, self.get_starttag_text() or f"<{tag}>"))
        return len(self.elements) - 1

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        index = self._child(tag, attrs)
        if tag not in HTML_VOID_ELEMENTS:
            self._open.append([tag, index, False, False])
        if tag == "style":
            self._style = []

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._child(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag == "style" and self._style is not None:
            self.styles.append("".join(self._style))
            self._style = None
        depth = next((depth for depth in range(len(self._open) - 1, -1, -1) if self._open[depth][0] == tag), None)
        if depth is None:
            return
        for _, index, has_element, has_text in self._open[depth:]:
            if has_element and has_text:
                self.mixed.add(index)
        del self._open[depth:]

    def handle_data(self, data: str) -> None:
        if self._style is not None:
            self._style.append(data)
        if self._open and data.strip():
            self._open[-1][3] = True


def neutralize_askama(text: str) -> str:
    # Control tags separate literal class tokens; expressions make the token
    # they touch dynamic, so it is never treated as a static class.
    return ASKAMA_TAG.sub(lambda match: DYNAMIC_MARKER if match.group(0).startswith("{{") else " ", text)


def design_static_classes(value: str) -> set[str]:
    return {token for token in value.split() if "{" not in token and "}" not in token}


def script_string_segments(source: str) -> list[str]:
    """Return JavaScript string and template literal text; ${} becomes a marker."""
    segments: list[str] = []
    index = 0
    previous = ""
    length = len(source)
    while index < length:
        char = source[index]
        if source.startswith("//", index):
            end = source.find("\n", index)
            index = length if end == -1 else end
        elif source.startswith("/*", index):
            end = source.find("*/", index + 2)
            index = length if end == -1 else end + 2
        elif char in "'\"":
            end = index + 1
            while end < length and source[end] not in {char, "\n"}:
                end += 2 if source[end] == "\\" else 1
            segments.append(source[index + 1 : end])
            index = end + 1
            previous = "value"
        elif char == "`":
            index = script_template(source, index, segments)
            previous = "value"
        elif char == "/" and (previous in SCRIPT_REGEX_PRECEDERS or previous in SCRIPT_REGEX_KEYWORDS or not previous):
            end = index + 1
            in_class = False
            while end < length and source[end] != "\n":
                if source[end] == "\\":
                    end += 2
                    continue
                if source[end] == "[":
                    in_class = True
                elif source[end] == "]":
                    in_class = False
                elif source[end] == "/" and not in_class:
                    break
                end += 1
            index = end + 1
            previous = "value"
        elif char.isalnum() or char in "_$":
            match = SCRIPT_IDENTIFIER.match(source, index)
            assert match is not None
            previous = match.group(0)
            index = match.end()
        else:
            if not char.isspace():
                previous = char
            index += 1
    return segments


def script_template(source: str, index: int, segments: list[str]) -> int:
    text: list[str] = []
    cursor = index + 1
    length = len(source)
    while cursor < length:
        char = source[cursor]
        if char == "\\":
            text.append(source[cursor : cursor + 2])
            cursor += 2
        elif char == "`":
            cursor += 1
            break
        elif source.startswith("${", cursor):
            depth = 1
            start = cursor + 2
            cursor = start
            while cursor < length and depth:
                current = source[cursor]
                if current in "'\"`":
                    nested: list[str] = []
                    if current == "`":
                        cursor = script_template(source, cursor, nested)
                    else:
                        end = cursor + 1
                        while end < length and source[end] not in {current, "\n"}:
                            end += 2 if source[end] == "\\" else 1
                        cursor = end + 1
                    continue
                if current == "{":
                    depth += 1
                elif current == "}":
                    depth -= 1
                cursor += 1
            segments.extend(script_string_segments(source[start : cursor - 1]))
            text.append(DYNAMIC_MARKER)
        else:
            text.append(char)
            cursor += 1
    segments.append("".join(text))
    return cursor


def design_script_classes(source: str) -> list[str]:
    classes: list[str] = []
    for segment in script_string_segments(source):
        for match in SCRIPT_CLASS.finditer(segment):
            token = match.group(0)
            if (
                token.endswith(("-", "_"))
                or segment.startswith(DYNAMIC_MARKER, match.end())
                or segment.endswith(DYNAMIC_MARKER, 0, match.start())
            ):
                continue
            classes.append(token)
    return classes


def design_rust_classes(source: str) -> list[str]:
    classes: list[str] = []
    for match in RUST_CLASS_ATTRIBUTE.finditer(sanitize_rust_source(source)):
        value = match.group(1) if match.group(1) is not None else match.group(2)
        classes.extend(sorted(item for item in design_static_classes(value) if item.startswith("cw-")))
    return classes


# ---------------------------------------------------------------------------
# Scan model


@dataclass(frozen=True)
class DesignSelector:
    text: str
    subjects: frozenset[str]
    hidden: bool


@dataclass(frozen=True)
class DesignDeclaration:
    file: str
    context: str
    name: str
    value: tuple[Any, ...]
    text: str
    important: bool
    subjects: frozenset[str]
    hidden: bool
    exempt: bool
    token_root: bool
    reduced_motion: bool
    inline: bool


@dataclass(frozen=True)
class DesignElement:
    file: str
    tag: str
    classes: frozenset[str]
    input_type: str
    style: str | None
    snippet: str
    mixed: bool


@dataclass
class DesignScan:
    declarations: list[DesignDeclaration]
    breakpoints: list[tuple[str, str, str, tuple[Any, ...]]]
    rule_subjects: list[tuple[str, frozenset[str]]]
    selector_classes: dict[str, set[str]]
    custom_properties: dict[str, set[str]]
    class_uses: list[tuple[str, str, str]]
    elements: list[DesignElement]


def design_file_kind(rel: str) -> str:
    if rel.endswith(".css"):
        return "css"
    if rel.endswith(".html"):
        return "template" if rel.startswith(f"{DESIGN_TEMPLATES}/") else "fixture"
    if rel.endswith(".js"):
        return "script"
    if rel.endswith(".rs"):
        return "rust"
    raise RuntimeError(f"unsupported design token input: {rel}")


def design_context(frames: tuple[str, ...]) -> str:
    return " { ".join(frames) + " }" * (len(frames) - 1) if frames else ""


def design_selector(prelude: tuple[Any, ...], parent: DesignSelector | None) -> DesignSelector:
    alternatives = css_split_commas(prelude)
    texts = [css_text(alternative, selector=True) for alternative in alternatives]
    subjects: set[str] = set()
    for alternative in alternatives:
        compound = css_last_compound(alternative)
        subjects |= css_compound_classes(compound)
        if parent is not None and any(css_is(value, "delim", "&") for value in compound):
            subjects |= parent.subjects
    hidden = bool(texts) and all(text.endswith("[hidden]") for text in texts)
    return DesignSelector(", ".join(texts), frozenset(subjects), hidden)


def design_scan(corpus: dict[str, str], policy: dict[str, Any]) -> DesignScan:
    scan = DesignScan([], [], [], {}, {}, [], [])
    token_files = set(policy["token_files"])
    for rel, text in sorted(corpus.items()):
        kind = design_file_kind(rel)
        if kind == "css":
            design_scan_stylesheet(scan, rel, text, token_file=rel in token_files)
        elif kind in {"template", "fixture"}:
            design_scan_markup(scan, rel, text, template=kind == "template")
        elif kind == "script":
            scan.class_uses.extend((rel, "<script string>", item) for item in design_script_classes(text))
        else:
            scan.class_uses.extend((rel, "<rust html>", item) for item in design_rust_classes(text))
    return scan


def design_scan_stylesheet(scan: DesignScan, rel: str, text: str, *, token_file: bool) -> None:
    items = css_items(css_component_values(css_tokens(text)), declarations=False)
    design_walk_css(scan, rel, items, (), None, token_file=token_file, exempt=False, reduced=False, token_root=False)


def design_walk_css(
    scan: DesignScan,
    rel: str,
    items: Any,
    frames: tuple[str, ...],
    selector: DesignSelector | None,
    *,
    token_file: bool,
    exempt: bool,
    reduced: bool,
    token_root: bool,
) -> None:
    for item in items:
        if isinstance(item, CssDeclaration):
            design_record_declaration(
                scan, rel, item, design_context(frames), selector,
                exempt=exempt, reduced=reduced, token_root=token_root, inline=False,
            )
        elif item.at is not None:
            frame = f"@{item.at} {css_text(item.prelude)}".strip()
            if item.at in CSS_BREAKPOINT_AT_RULES:
                scan.breakpoints.append((rel, design_context(frames + (frame,)), item.at, item.prelude))
            if item.block is not None:
                design_walk_css(
                    scan, rel, item.block, frames + (frame,), selector,
                    token_file=token_file,
                    exempt=exempt or item.at in CSS_EXEMPT_AT_RULES,
                    reduced=reduced or (item.at == "media" and bool(CSS_REDUCED_MOTION.search(frame))),
                    token_root=False,
                )
        else:
            current = design_selector(item.prelude, selector)
            scan.selector_classes.setdefault(rel, set()).update(css_selector_classes(item.prelude))
            if not exempt:
                scan.rule_subjects.append((rel, current.subjects))
            design_walk_css(
                scan, rel, item.block, frames + (current.text,), current,
                token_file=token_file,
                exempt=exempt,
                reduced=reduced,
                token_root=token_file and not frames and selector is None and current.text == ":root",
            )


def design_record_declaration(
    scan: DesignScan,
    rel: str,
    declaration: CssDeclaration,
    context: str,
    selector: DesignSelector | None,
    *,
    exempt: bool,
    reduced: bool,
    token_root: bool,
    inline: bool,
) -> None:
    if declaration.name.startswith("--"):
        scan.custom_properties.setdefault(rel, set()).add(declaration.name)
    scan.declarations.append(
        DesignDeclaration(
            file=rel,
            context=context,
            name=declaration.name,
            value=declaration.value,
            text=css_text(declaration.value),
            important=declaration.important,
            subjects=selector.subjects if selector else frozenset(),
            hidden=selector.hidden if selector else False,
            exempt=exempt,
            token_root=token_root,
            reduced_motion=reduced,
            inline=inline,
        )
    )


def design_scan_markup(scan: DesignScan, rel: str, text: str, *, template: bool) -> None:
    parser = DesignMarkupParser()
    parser.feed(neutralize_askama(text) if template else text)
    parser.close()
    for stylesheet in parser.styles:
        design_scan_stylesheet(scan, rel, stylesheet, token_file=False)
    for position, (tag, attributes, start) in enumerate(parser.elements):
        classes: set[str] = set()
        style: str | None = None
        input_type = ""
        for name, value in attributes:
            if name == "class":
                classes |= design_static_classes(value or "")
            elif name == "style":
                style = (style + ";" if style else "") + (value or "")
            elif name == "type":
                input_type = (value or "").strip().lower()
        scan.class_uses.extend((rel, f"<{tag}>", item) for item in sorted(classes) if item.startswith("cw-"))
        if style is not None:
            for item in css_items(css_component_values(css_tokens(style)), declarations=True):
                if isinstance(item, CssDeclaration):
                    design_record_declaration(
                        scan, rel, item, f"<{tag} style>", None,
                        exempt=False, reduced=False, token_root=False, inline=True,
                    )
        scan.elements.append(
            DesignElement(
                file=rel,
                tag=tag,
                classes=frozenset(classes),
                input_type=input_type,
                style=css_normalize(style) if style is not None else None,
                snippet=re.sub(r"\s+", " ", start).strip(),
                mixed=position in parser.mixed,
            )
        )


# ---------------------------------------------------------------------------
# Rules


def design_unprefixed(name: str) -> str:
    return CSS_VENDOR_PREFIX.sub("", name)


def design_property_kind(name: str, table: dict[str, list[str]]) -> str | None:
    best: tuple[int, str] | None = None
    for kind, patterns in table.items():
        for pattern in patterns:
            if fnmatchcase(name, pattern):
                score = len(pattern.replace("*", "")) + (1000 if "*" not in pattern else 0)
                if best is None or score > best[0]:
                    best = (score, kind)
    return best[1] if best else None


def design_matches(name: str, patterns: list[str]) -> bool:
    return any(fnmatchcase(name, pattern) for pattern in patterns)


def design_control(name: str, controls: list[str]) -> bool:
    return any(name == control or name.startswith(f"{control}--") for control in controls)


def design_visual(name: str, classes: Any, policy: dict[str, Any]) -> bool:
    name = design_unprefixed(name)
    if name.startswith("--"):
        return False
    ownership = policy["ownership_properties"]
    if design_matches(name, ownership["visual"]):
        return True
    return design_matches(name, ownership["control_visual"]) and any(
        design_control(item, policy["control_classes"]) for item in classes
    )


def design_primitives(scan: DesignScan, policy: dict[str, Any]) -> dict[str, str]:
    primitives: dict[str, str] = {}
    for core_file in policy["core_files"]:
        for rel, subjects in scan.rule_subjects:
            if rel == core_file:
                for item in sorted(subjects):
                    if item.startswith("cw-"):
                        primitives.setdefault(item, core_file)
    return primitives


def design_literal(
    declaration: DesignDeclaration, policy: dict[str, Any], primitives: dict[str, str]
) -> bool:
    value = declaration.value
    if css_has_var_fallback(value) or css_has_data_uri(value):
        return True
    if declaration.name.startswith("--"):
        return css_custom_literal(value)
    name = design_unprefixed(declaration.name)
    kind = design_property_kind(name, policy["literal_properties"])
    if kind is None:
        return False
    if kind == "layout_size":
        return bool(declaration.subjects & primitives.keys()) and css_value_literal(value, kind, name)
    if kind == "font":
        return any(
            css_value_literal(part, "typography", "font-size" if index == 0 else "line-height")
            for index, part in enumerate(css_font_parts(value))
        )
    return css_value_literal(value, kind, name)


def design_token_violations(
    corpus: dict[str, str], policy: dict[str, Any]
) -> tuple[list[str], list[str]]:
    """Return every violation fingerprint (a multiset) and policy-level failures."""
    scan = design_scan(corpus, policy)
    violations: list[str] = []
    failures: list[str] = []
    core = set(policy["core_files"])
    isolated = set(policy["isolated_token_files"])
    primitives = design_primitives(scan, policy)

    def emit(rule: str, rel: str, context: str, name: str, value: str) -> None:
        violations.append(design_fingerprint(rule, rel, context, name, value))

    # R1 literal: values outside the token :root blocks and unlisted breakpoints.
    for declaration in scan.declarations:
        if declaration.exempt:
            continue
        if declaration.token_root:
            if css_has_data_uri(declaration.value) and not declaration.name.startswith("--icon-"):
                emit("literal", declaration.file, declaration.context, declaration.name, declaration.text)
        elif design_literal(declaration, policy, primitives):
            emit("literal", declaration.file, declaration.context, declaration.name, declaration.text)
    breakpoints = {css_length_key(css_significant(css_tokens(item))[0]) for item in policy["breakpoints"]}
    for rel, context, at, prelude in scan.breakpoints:
        for length in css_prelude_lengths(prelude):
            if length not in breakpoints:
                emit("literal", rel, context, f"@{at}", length)

    # R2 forbidden: !important, removed focus outlines, and tracking outside core.
    # An isolated token file is its own design system: its tracking and uppercase
    # are allowed (letter-spacing values are still literals checked by R1).
    for declaration in scan.declarations:
        name = design_unprefixed(declaration.name)
        if declaration.important and not declaration.hidden and not declaration.reduced_motion:
            emit("forbidden", declaration.file, declaration.context, declaration.name, f"{declaration.text} !important")
        if (name == "outline" and css_outline_removed(declaration.value)) or (
            name == "outline-style" and declaration.text.lower() == "none"
        ):
            emit("forbidden", declaration.file, declaration.context, declaration.name, declaration.text)
        if declaration.file not in core and declaration.file not in isolated and (
            name == "letter-spacing"
            or (
                name == "text-transform"
                and any(css_is(atom, "ident", "uppercase") for atom, _ in css_value_atoms(declaration.value))
            )
        ):
            emit("forbidden", declaration.file, declaration.context, declaration.name, declaration.text)

    # R3 ownership: primitives are styled only in core; one file owns each class.
    owners: dict[str, list[str]] = {}
    for declaration in scan.declarations:
        if declaration.exempt or declaration.inline:
            continue
        owned = declaration.subjects & primitives.keys()
        if declaration.file not in core and owned and design_visual(declaration.name, owned, policy):
            emit("ownership", declaration.file, declaration.context, declaration.name, declaration.text)
        if declaration.file.endswith(".css"):
            for item in declaration.subjects:
                files = owners.setdefault(item, [])
                if declaration.file not in files and design_visual(declaration.name, {item}, policy):
                    files.append(declaration.file)
    # Core sheets own first, then production route sheets, then fixture chrome.
    rank = {rel: index for index, rel in enumerate(policy["core_files"])}
    for item, files in sorted(owners.items()):
        ordered = sorted(
            files,
            key=lambda rel: (rank.get(rel, len(rank) + int(rel.startswith(f"{DESIGN_FIXTURES}/"))), rel),
        )
        for extra in ordered[1:]:
            emit("ownership", extra, f".{item}", "visual-owner", ordered[0])

    # R4 undefined: custom properties and cw- classes must be defined.
    shared_properties: set[str] = set()
    shared_classes: set[str] = set()
    for rel, names in scan.custom_properties.items():
        if rel.endswith(".css") and rel not in isolated:
            shared_properties |= names
    for rel, names in scan.selector_classes.items():
        if rel.endswith(".css"):
            shared_classes |= names
    for declaration in scan.declarations:
        names = css_var_names(declaration.value)
        if not names:
            continue
        own = scan.custom_properties.get(declaration.file, set())
        if declaration.file in isolated:
            defined = own
        elif declaration.file.endswith(".css"):
            defined = shared_properties
        else:
            defined = shared_properties | own
        for name in sorted(names - defined):
            emit("undefined", declaration.file, declaration.context, declaration.name, f"var({name})")
    hooks = policy["js_hook_classes"]
    used_hooks: set[str] = set()
    for rel, context, item in scan.class_uses:
        local = scan.selector_classes.get(rel, set()) if not rel.endswith(".css") else set()
        if item in shared_classes or item in local:
            continue
        if item in hooks:
            used_hooks.add(item)
            continue
        emit("undefined", rel, context, "class", item)
    for item in sorted(set(hooks) - used_hooks):
        failures.append(f"js_hook_classes entry {item} is defined in CSS or no longer used; remove it")

    # R5 markup: native controls carry their primitive class; no inline styles.
    # A .cw-button that holds an icon or other element keeps its label in an
    # element too: the capital-height trim cannot reach a bare text node.
    for element in scan.elements:
        key = f"input:{element.input_type}" if element.tag == "input" else element.tag
        required = DESIGN_MARKUP_REQUIRED.get(key)
        if required and not element.classes & set(required):
            emit("markup", element.file, f"<{element.tag}>", "class", element.snippet)
        if element.tag == "button" and not any(item.startswith("cw-") for item in element.classes):
            emit("markup", element.file, "<button>", "class", element.snippet)
        if element.style is not None:
            emit("markup", element.file, f"<{element.tag}>", "style", element.style)
        if element.mixed and "cw-button" in element.classes:
            emit("markup", element.file, f"<{element.tag}>", "label", element.snippet)

    # R6 gallery: every core primitive appears in the component gallery.
    gallery = policy["gallery_file"]
    if gallery not in corpus:
        failures.append(f"design gallery is missing: {gallery}")
    shown = {item for rel, _, item in scan.class_uses if rel == gallery}
    for item, owner in sorted(primitives.items()):
        if item not in shown:
            emit("gallery", gallery, f".{item}", "primitive", owner)

    return violations, failures


# ---------------------------------------------------------------------------
# Self-test


DESIGN_SELF_TEST_STYLES = f"{DESIGN_PACKAGE}/styles.css"
DESIGN_SELF_TEST_COMPONENTS = f"{DESIGN_PACKAGE}/components.css"
DESIGN_SELF_TEST_ROUTE = f"{DESIGN_PACKAGE}/routes/fixture.css"
DESIGN_SELF_TEST_OTHER_ROUTE = f"{DESIGN_PACKAGE}/routes/other.css"
DESIGN_SELF_TEST_TEMPLATE = f"{DESIGN_TEMPLATES}/fixture.html"
DESIGN_SELF_TEST_FIXTURE = f"{DESIGN_FIXTURES}/fixture.html"
DESIGN_SELF_TEST_SCRIPT = f"{DESIGN_PACKAGE}/dashboard.js"
DESIGN_SELF_TEST_RUST = f"{DESIGN_RUST_ROUTES}/fixture.rs"
DESIGN_SELF_TEST_CHEVRON = (
    "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='13' height='13' "
    "viewBox='0 0 24 24' fill='none' stroke='%23878787' stroke-width='2'%3E%3Cpath "
    "d='m6 9 6 6 6-6'/%3E%3C/svg%3E\")"
)


def design_self_test_base(policy: dict[str, Any]) -> dict[str, str]:
    return {
        DESIGN_SELF_TEST_STYLES: (
            ":root { --space-2: 0.5rem; --fg: #fff; --tracking: 0.08em; --text-sm: 0.875rem; "
            "--font-sans: Inter, sans-serif; }\n"
            ".cw-button { color: var(--fg); padding: var(--space-2); }\n"
        ),
        DESIGN_SELF_TEST_COMPONENTS: ".cw-card { padding: var(--space-2); }\n",
        policy["gallery_file"]: (
            '<!doctype html><main><button class="cw-button">Go</button>'
            '<div class="cw-card"></div></main>\n'
        ),
    }


def design_tokens_self_test(policy: dict[str, Any], violations: list[str], corpus: dict[str, str]) -> int:
    cases = 0

    def expect(label: str, condition: bool) -> None:
        nonlocal cases
        cases += 1
        if not condition:
            raise RuntimeError(f"design token self-test failed: {label}")

    # The real tree has no violations.
    expect("real tree has no violations", not violations and not design_token_failures(violations))

    # Tokenizer: opaque data URIs, comments, nested blocks, and !important.
    chevron = css_items(
        css_component_values(
            css_tokens(
                ".cw-environment-create .cw-select { appearance: none; /* a: b; } */ padding-right: 30px; "
                f"background-image: {DESIGN_SELF_TEST_CHEVRON}; background-repeat: no-repeat !important; }}"
            )
        ),
        declarations=False,
    )
    declarations = [item for item in chevron[0].block if isinstance(item, CssDeclaration)]
    expect(
        "data URI chevron stays one declaration",
        [item.name for item in declarations]
        == ["appearance", "padding-right", "background-image", "background-repeat"]
        and css_has_data_uri(declarations[2].value)
        and declarations[3].important
        and css_text(declarations[3].value) == "no-repeat",
    )
    unquoted = css_items(
        css_component_values(
            css_tokens(".x { background: url(data:image/svg+xml;utf8,<svg xmlns='a'><path d='M0 0'/></svg>); color: red; }")
        ),
        declarations=False,
    )
    expect(
        "unquoted data URI is opaque",
        [item.name for item in unquoted[0].block] == ["background", "color"],
    )
    nested = css_items(
        css_component_values(css_tokens("@media (max-width: 48rem) { .a { &:hover { color: red; } } }")),
        declarations=False,
    )
    expect(
        "nested blocks parse",
        nested[0].at == "media"
        and isinstance(nested[0].block[0].block[0], CssRule)
        and nested[0].block[0].block[0].block[0].name == "color",
    )
    expect("subject is the rightmost compound", css_subject_classes(".cw-a .x > .y.z") == {"y", "z"})
    expect("is() alternatives expand", css_subject_classes(".x :is(.cw-a, .b .cw-c)") == {"cw-a", "cw-c"})
    expect(
        "not/has/where arguments are ignored",
        css_subject_classes(".x:not(.cw-a):has(.cw-b):where(.cw-c)") == {"x"},
    )
    expect(
        "Askama in attributes",
        design_static_classes(
            neutralize_askama('a {% if on %}cw-b{% else %}cw-c{% endif %} cw-d--{{ tone }} {# note #}')
        )
        == {"a", "cw-b", "cw-c"},
    )
    expect(
        "script strings, templates and regex literals",
        design_script_classes(
            "const re = /\"cw-regex\"/g; // cw-comment\n"
            "el.className = `cw-a cw-b--${tone} ${ok ? 'cw-c' : ''}`; q('.cw-d, #cw-id');"
        )
        == ["cw-c", "cw-a", "cw-d"],
    )

    base = design_self_test_base(policy)
    base_violations, base_failures = design_token_violations(base, policy)
    expect("self-test base is clean", not base_violations and not base_failures)

    def violations_for(extra: dict[str, str]) -> list[str]:
        found, failed = design_token_violations({**base, **extra}, policy)
        if failed:
            raise RuntimeError(f"design token self-test policy failure: {failed}")
        return found

    route = DESIGN_SELF_TEST_ROUTE
    template = DESIGN_SELF_TEST_TEMPLATE
    bad: list[tuple[str, str, dict[str, str], str | None]] = [
        ("literal font-size", "literal", {route: ".x { font-size: 13px; }"}, f"literal|{route}|.x|font-size|13px"),
        ("literal font shorthand", "literal", {route: ".x { font: 600 12px/16px var(--font-sans); }"}, None),
        ("calc recursion", "literal", {route: ".x { padding: calc(var(--space-2) + 3px); }"}, None),
        ("clamp recursion", "literal", {route: ".x { font-size: clamp(1rem, 2vw, var(--text-sm)); }"}, None),
        ("var fallback", "literal", {route: ".x { color: var(--fg, #fff); }"}, None),
        ("custom property literal", "literal", {route: ".x { --create-gap: 18px; }"}, f"literal|{route}|.x|--create-gap|18px"),
        ("named colour", "literal", {route: ".x { background: rebeccapurple; }"}, None),
        ("thick border", "literal", {route: ".x { border: 3px solid var(--fg); }"}, None),
        ("primitive layout size", "literal", {route: ".x .cw-card { max-width: 40rem; }"}, None),
        ("line-height number", "literal", {route: ".x { line-height: 1.4; }"}, None),
        (
            "unlisted breakpoint",
            "literal",
            {route: "@media (max-width: 30rem) { .x { display: none; } }"},
            f"literal|{route}|@media (max-width: 30rem)|@media|30rem",
        ),
        ("data URI outside token", "literal", {route: f".x {{ background-image: {DESIGN_SELF_TEST_CHEVRON}; }}"}, None),
        ("inline style literal", "literal", {DESIGN_SELF_TEST_FIXTURE: '<p class="cw-card" style="color: #fff">x</p>'}, None),
        ("!important", "forbidden", {route: ".x { overflow: visible !important; }"}, f"forbidden|{route}|.x|overflow|visible !important"),
        (
            "!important in an ordinary media query",
            "forbidden",
            {route: "@media (max-width: 48rem) { .x { display: none !important; } }"},
            None,
        ),
        ("!important below a hidden ancestor", "forbidden", {route: "[hidden] .x { display: none !important; }"}, None),
        ("outline none", "forbidden", {route: ".x:focus-visible { outline: none; }"}, None),
        ("outline zero", "forbidden", {route: ".x:focus { outline: 0; }"}, None),
        ("route letter-spacing", "forbidden", {route: ".x { letter-spacing: var(--tracking); }"}, None),
        ("route uppercase", "forbidden", {route: ".x { text-transform: uppercase; }"}, None),
        ("primitive override", "ownership", {route: ".x .cw-button { color: var(--fg); }"}, f"ownership|{route}|.x .cw-button|color|var(--fg)"),
        ("is() primitive override", "ownership", {route: ".x :is(.cw-card, .y) { padding: var(--space-2); }"}, None),
        ("control height override", "ownership", {route: ".x .cw-button { min-height: 100dvh; }"}, None),
        (
            "duplicate visual owner",
            "ownership",
            {route: ".x-panel { color: var(--fg); }", DESIGN_SELF_TEST_OTHER_ROUTE: ".x-panel { background: var(--fg); }"},
            f"ownership|{DESIGN_SELF_TEST_OTHER_ROUTE}|.x-panel|visual-owner|{route}",
        ),
        ("undefined var", "undefined", {route: ".x { color: var(--missing); }"}, f"undefined|{route}|.x|color|var(--missing)"),
        ("undefined template class", "undefined", {template: '<div class="cw-missing"></div>'}, f"undefined|{template}|<div>|class|cw-missing"),
        ("undefined Askama class", "undefined", {template: '<div class="cw-card{% if open %} cw-missing{% endif %}"></div>'}, None),
        ("undefined script class", "undefined", {DESIGN_SELF_TEST_SCRIPT: 'el.className = "cw-card cw-missing";'}, None),
        ("undefined Rust class", "undefined", {DESIGN_SELF_TEST_RUST: 'fn f() -> &\'static str { "<p class=\\"cw-missing\\">x</p>" }'}, None),
        ("bare select", "markup", {template: '<select name="a"></select>'}, f'markup|{template}|<select>|class|<select name="a">'),
        ("bare textarea", "markup", {template: "<textarea></textarea>"}, None),
        ("bare checkbox", "markup", {template: '<input type="checkbox" {% if on %}checked{% endif %}>'}, None),
        ("bare radio", "markup", {template: '<input type="radio">'}, None),
        ("bare details", "markup", {template: "<details><summary>x</summary></details>"}, None),
        ("bare button", "markup", {template: '<button type="button">x</button>'}, None),
        ("template style attribute", "markup", {template: '<p class="cw-card" style="display: none">x</p>'}, None),
        ("template content", "markup", {template: "<template><select></select></template>"}, None),
        (
            "bare label beside an icon",
            "markup",
            {template: '<button class="cw-button" type="button"><svg aria-hidden="true"><use href="#i"/></svg>Add</button>'},
            f'markup|{template}|<button>|label|<button class="cw-button" type="button">',
        ),
        ("bare Askama label beside an icon", "markup", {template: '<summary class="cw-button">{{ name }}<svg></svg></summary>'}, None),
        ("bare label beside a hidden name", "markup", {DESIGN_SELF_TEST_FIXTURE: '<a class="cw-button" href="/x">Open<span> docs</span></a>'}, None),
        ("bare label after a void element", "markup", {template: '<button class="cw-button"><img alt="">Add</button>'}, None),
        (
            "gallery gap",
            "gallery",
            {DESIGN_SELF_TEST_STYLES: base[DESIGN_SELF_TEST_STYLES] + ".cw-new { color: var(--fg); }\n"},
            f"gallery|{policy['gallery_file']}|.cw-new|primitive|{DESIGN_SELF_TEST_STYLES}",
        ),
    ]
    for label, rule, extra, fingerprint in bad:
        found = violations_for(extra)
        expect(f"{rule} rejects {label}", any(item.startswith(f"{rule}|") for item in found))
        if fingerprint is not None:
            expect(f"{rule} fingerprint for {label}: {found}", fingerprint in found)

    definitions = f"{DESIGN_PACKAGE}/routes/definitions.css"
    good: list[tuple[str, dict[str, str]]] = [
        (
            "tokenized declarations",
            {
                route: (
                    ".x { font-size: var(--text-sm); padding: calc(var(--space-2) * 2); margin: 0 auto; "
                    "border: 1px solid var(--fg); outline: 2px solid var(--fg); width: 40rem; min-height: 100dvh; "
                    "gap: var(--space-2); color: currentColor; background: transparent; line-height: normal; "
                    "grid-template-columns: repeat(2, minmax(0, 1fr)); inset: 0 auto auto 50%; "
                    "font: inherit; --alias: var(--space-2); }"
                )
            },
        ),
        ("listed breakpoint", {route: "@media (max-width: 48rem) { .x { display: none; } }"}),
        (
            "font-face and keyframes are exempt",
            {
                route: (
                    '@font-face { font-family: "Fixture"; src: url("/f.woff2") format("woff2"); font-weight: 400; }\n'
                    "@keyframes pulse { from { opacity: 0.4; transform: translateY(4px); } }"
                )
            },
        ),
        (
            "hidden and reduced-motion !important",
            {
                route: (
                    "[hidden], .x[hidden] { display: none !important; }\n"
                    "@media (prefers-reduced-motion: reduce) { .x { animation: none !important; } }"
                )
            },
        ),
        (
            "core tracking and uppercase",
            {
                DESIGN_SELF_TEST_STYLES: base[DESIGN_SELF_TEST_STYLES]
                + ".cw-button { letter-spacing: var(--tracking); text-transform: uppercase; }\n"
            },
        ),
        (
            "layout-only primitive placement and ignored pseudo arguments",
            {
                route: (
                    ".x .cw-button { margin: 0; display: grid; width: 100%; }\n"
                    ".cw-button .x, .x:not(.cw-button), .x:has(.cw-card), .x:where(.cw-card) { color: var(--fg); }\n"
                    ".x .cw-card { min-height: 100vh; }"
                )
            },
        ),
        (
            "dynamic and local classes",
            {
                definitions: ".cw-select, .cw-textarea, .cw-checkbox, .cw-radio, .cw-menu, .cw-button--outline { display: block; }",
                template: (
                    '<div class="cw-card cw-status--{{ tone }}"></div>'
                    '<select class="cw-select"></select><textarea class="cw-textarea"></textarea>'
                    '<input type="checkbox" class="cw-checkbox" {% if on %}checked{% endif %}>'
                    '<input type="radio" class="cw-radio"><details class="cw-menu"><summary>x</summary></details>'
                    '<button class="{% if a %}cw-button{% else %}cw-button cw-button--outline{% endif %}" '
                    "hx-vals='{\"a\": \"{{ b }}\"}'>x</button><template><select class=\"cw-select\"></select></template>"
                    '<summary class="cw-button">\n  {% if a %}<svg aria-hidden="true"><use href="#i"/></svg>{% endif %}\n  '
                    "<span>{{ label }}</span>\n</summary>"
                ),
                DESIGN_SELF_TEST_FIXTURE: (
                    "<style>.cw-local { --local: var(--fg); color: var(--local); }</style>"
                    '<p class="cw-local">x</p>'
                ),
                DESIGN_SELF_TEST_SCRIPT: "el.className = `cw-card cw-status--${tone}`; q('.cw-button');",
                DESIGN_SELF_TEST_RUST: (
                    'fn f(tone: &str) -> String { format!("<p class=\\"cw-card cw-status--{tone}\\">x</p>") }\n'
                    '#[cfg(test)]\nmod tests { const X: &str = "<p class=\\"cw-missing\\">"; }\n'
                ),
            },
        ),
        (
            "gallery covers primitive",
            {
                DESIGN_SELF_TEST_STYLES: base[DESIGN_SELF_TEST_STYLES] + ".cw-new { color: var(--fg); }\n",
                policy["gallery_file"]: base[policy["gallery_file"]] + '<span class="cw-new"></span>\n',
            },
        ),
    ]
    for label, extra in good:
        found = violations_for(extra)
        expect(f"accepts {label}: {found}", not found)

    # Tracking and uppercase: an isolated token file may use them as tokens; the
    # exemption does not extend to any other non-core route.
    marketing = f"{DESIGN_PACKAGE}/routes/marketing.css"
    isolated_policy = copy.deepcopy(policy)
    isolated_policy["token_files"] = [*policy["token_files"], marketing]
    isolated_policy["isolated_token_files"] = [*policy["isolated_token_files"], marketing]
    marketing_css = (
        ":root { --tracking-label: 0.04em; }\n"
        ".x { letter-spacing: var(--tracking-label); text-transform: uppercase; }\n"
    )
    found, failed = design_token_violations({**base, marketing: marketing_css}, isolated_policy)
    expect(f"isolated token file may use tracking and uppercase: {found} {failed}", not found and not failed)
    found, _ = design_token_violations(
        {**base, marketing: marketing_css.replace("var(--tracking-label)", "0.04em")}, isolated_policy
    )
    expect(
        f"isolated token file tracking is still a token: {found}",
        found == [f"literal|{marketing}|.x|letter-spacing|0.04em"],
    )
    found, _ = design_token_violations(
        {**base, marketing: marketing_css, route: ".y { letter-spacing: var(--tracking); text-transform: uppercase; }"},
        isolated_policy,
    )
    expect(
        f"non-isolated route still rejects tracking and uppercase: {found}",
        f"forbidden|{route}|.y|letter-spacing|var(--tracking)" in found
        and f"forbidden|{route}|.y|text-transform|uppercase" in found
        and not any(f"|{marketing}|" in item for item in found),
    )

    hooked = copy.deepcopy(policy)
    hooked["js_hook_classes"] = {"cw-hook": "fixture hook"}
    hook_violations, hook_failures = design_token_violations(
        {**base, DESIGN_SELF_TEST_SCRIPT: 'el.classList.add("cw-hook");'}, hooked
    )
    expect("JS hook allowlist admits a used hook", not hook_violations and not hook_failures)
    expect("unused JS hook is stale", bool(design_token_violations(base, hooked)[1]))

    # No baseline: every violation fails and is reported under its file and rule.
    first = f"literal|{route}|.x|color|red"
    reported = design_token_failures([first, first])
    expect(
        "every violation fails, repeats included",
        reported[:2] == ["2 violations (selector|property|value); fix each one", f"{route} [literal]: 2"],
    )
    return cases
