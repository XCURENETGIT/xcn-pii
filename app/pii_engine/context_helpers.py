from __future__ import annotations

from collections import defaultdict
from typing import Any, DefaultDict, Dict, List, Pattern, Tuple

from .common import *

def _split_sentences(text: str) -> List[Tuple[int, int]]:
    """Return list of (start, end) spans for simple sentence splitting.

    Splits on sentence-ending punctuation (., ?, !, 洹몃━怨??쒓? 臾몄옣遺?? and newlines.
    This is a light-weight splitter (no external deps) suitable for extracting
    a few surrounding sentences as context.
    """
    if not text:
        return []

    spans: List[Tuple[int, int]] = []
    # Use a regex to capture sentence chunks
    pattern = re.compile(r"[^.!?\n]+(?:[.!?]+|\n+|$)", re.MULTILINE | re.DOTALL)
    pos = 0
    for m in pattern.finditer(text):
        s = m.start()
        e = m.end()
        # normalize bounds
        if s < 0:
            s = 0
        if e > len(text):
            e = len(text)
        if e > s:
            spans.append((s, e))
    if not spans:
        spans = [(0, len(text))]
    return spans


def _get_context_window_from_spans(
    text: str,
    spans: List[Tuple[int, int]],
    start: int,
    end: int,
    window_sentences: int = 2,
) -> Tuple[str, int, int]:
    if not spans:
        return ("", 0, 0)

    idx_start = None
    idx_end = None
    for i, (s, e) in enumerate(spans):
        if idx_start is None and s <= start < e:
            idx_start = i
        if idx_end is None and s <= end <= e:
            idx_end = i
        if idx_start is not None and idx_end is not None:
            break

    if idx_start is None:
        for i, (s, e) in enumerate(spans):
            if start < e:
                idx_start = i
                break
    if idx_start is None:
        idx_start = 0

    if idx_end is None:
        for i in range(len(spans) - 1, -1, -1):
            s, e = spans[i]
            if end >= s:
                idx_end = i
                break
    if idx_end is None:
        idx_end = len(spans) - 1

    s_idx = max(0, idx_start - window_sentences)
    e_idx = min(len(spans) - 1, idx_end + window_sentences)

    abs_start = spans[s_idx][0]
    abs_end = spans[e_idx][1]
    return text[abs_start:abs_end], abs_start, abs_end


def _get_context_window(text: str, start: int, end: int, window_sentences: int = 2) -> Tuple[str, int, int]:
    """Return context snippet and absolute start/end covering window_sentences
    before the sentence that contains (start) and after the sentence that contains (end).
    Returns (snippet, abs_start, abs_end).
    """
    return _get_context_window_from_spans(
        text=text,
        spans=_split_sentences(text),
        start=start,
        end=end,
        window_sentences=window_sentences,
    )


def _clip_snippet_around_span(
    snippet: str,
    snippet_abs_start: int,
    match_start: int,
    match_end: int,
    max_chars: int,
) -> str:
    raw = str(snippet or "")
    limit = max(0, int(max_chars))
    if not raw or limit <= 0 or len(raw) <= limit:
        return raw
    rel_s = max(0, int(match_start) - int(snippet_abs_start))
    rel_e = max(rel_s, int(match_end) - int(snippet_abs_start))
    match_center = (rel_s + rel_e) // 2
    half = limit // 2
    clip_s = max(0, match_center - half)
    clip_e = min(len(raw), clip_s + limit)
    if clip_e - clip_s < limit:
        clip_s = max(0, clip_e - limit)
    return raw[clip_s:clip_e]


def _looks_like_header_cell(cell: str) -> bool:
    s = str(cell or "").strip()
    if not s:
        return False
    if len(s) > 64:
        return False
    if "@" in s:
        return False
    if not re.search(r"[A-Za-z가-힣]", s):
        return False
    digits = sum(1 for ch in s if ch.isdigit())
    if digits and (float(digits) / float(len(s))) >= 0.4:
        return False
    return True


def _split_cells_with_spans(line: str) -> List[Tuple[str, int, int]]:
    """Split a table-like row into cells and keep (text,start,end) spans.

    Priority:
    1) tab-separated
    2) multi-space separated (2+)
    3) single-space token fallback
    """
    s = str(line or "")
    if not s:
        return []

    out: List[Tuple[str, int, int]] = []
    if "\t" in s:
        start = 0
        for part in s.split("\t"):
            end = start + len(part)
            out.append((part.strip(), start, end))
            start = end + 1
        return out

    # Prefer explicit column gaps first.
    multi = list(re.finditer(r"\S(?:.*?\S)?(?=\s{2,}|$)", s))
    if len(multi) >= 2:
        for m in multi:
            out.append((m.group(0).strip(), m.start(), m.end()))
        return out

    # Fallback: single-space tokenization.
    for m in re.finditer(r"\S+", s):
        out.append((m.group(0).strip(), m.start(), m.end()))
    return out


def _extract_tabular_header_hint(
    text: str,
    start: int,
    end: int,
    max_lines_up: int = 64,
    max_distance_chars: int = 8000,
) -> str:
    """Return likely column header text for a tabular row (TSV-like copy from Excel).

    Finds the current line/column for span(start,end), then scans upward lines to find
    a header-like cell in the same column.
    """
    if not text:
        return ""
    s = max(0, min(int(start), len(text)))
    e = max(s, min(int(end), len(text)))
    line_start = text.rfind("\n", 0, s) + 1
    line_end = text.find("\n", e)
    if line_end < 0:
        line_end = len(text)
    row = text[line_start:line_end]
    row_cells = _split_cells_with_spans(row)
    if len(row_cells) < 2:
        return ""
    col_pos = max(0, min(s - line_start, len(row)))

    col_idx = 0
    found_idx = False
    for i, (_, cs, ce) in enumerate(row_cells):
        if cs <= col_pos <= ce:
            col_idx = i
            found_idx = True
            break
    if not found_idx:
        # nearest cell by start position
        best_i = 0
        best_d = None
        for i, (_, cs, _ce) in enumerate(row_cells):
            d = abs(cs - col_pos)
            if best_d is None or d < best_d:
                best_d = d
                best_i = i
        col_idx = best_i

    def _best_header_cell_by_pos(cells: List[Tuple[str, int, int]], pos: int) -> str:
        best = ""
        best_d = None
        for txt, cs, _ce in cells:
            if not _looks_like_header_cell(txt):
                continue
            d = abs(int(cs) - int(pos))
            if best_d is None or d < best_d:
                best_d = d
                best = txt
        return best

    scanned = 0
    cur_end = line_start - 1
    while cur_end >= 0 and scanned < max(1, int(max_lines_up)):
        if (line_start - cur_end) > max(1, int(max_distance_chars)):
            break
        prev_start = text.rfind("\n", 0, cur_end) + 1
        prev_line = text[prev_start:cur_end]
        prev_cells = _split_cells_with_spans(prev_line)
        if prev_cells:
            cand = ""
            if col_idx < len(prev_cells):
                cand = prev_cells[col_idx][0]
            # If direct index fails or is not header-like, fallback to nearest header cell.
            if (not cand) or (not _looks_like_header_cell(cand)):
                cand = _best_header_cell_by_pos(prev_cells, col_pos)
            if _looks_like_header_cell(cand):
                return cand
            # Final fallback for single-space-formatted tables:
            # return the whole line so label regex can still match header words.
            header_like_cells = [txt for txt, _s, _e in prev_cells if _looks_like_header_cell(txt)]
            if len(header_like_cells) >= 2:
                return str(prev_line).strip()
        cur_end = prev_start - 1
        scanned += 1
    return ""


def _extract_tabular_header_line_hint(
    text: str,
    start: int,
    end: int,
    label_res: List[Pattern],
    max_lines_up: int = 64,
    max_distance_chars: int = 8000,
) -> str:
    """Fallback: find a nearby table-like header line matching label patterns."""
    if not text or not label_res:
        return ""
    s = max(0, min(int(start), len(text)))
    e = max(s, min(int(end), len(text)))
    line_start = text.rfind("\n", 0, s) + 1
    _line_end = text.find("\n", e)
    if _line_end < 0:
        _line_end = len(text)

    scanned = 0
    cur_end = line_start - 1
    while cur_end >= 0 and scanned < max(1, int(max_lines_up)):
        if (line_start - cur_end) > max(1, int(max_distance_chars)):
            break
        prev_start = text.rfind("\n", 0, cur_end) + 1
        prev_line = text[prev_start:cur_end]
        cells = _split_cells_with_spans(prev_line)
        header_like = [txt for txt, _cs, _ce in cells if _looks_like_header_cell(txt)]
        if len(header_like) >= 2 and any(rx.search(prev_line) for rx in label_res):
            return str(prev_line).strip()
        cur_end = prev_start - 1
        scanned += 1
    return ""


def _line_bounds(text: str, pos: int) -> Tuple[int, int]:
    if not text:
        return (0, 0)
    p = max(0, min(int(pos), len(text)))
    s = text.rfind("\n", 0, p) + 1
    e = text.find("\n", p)
    if e < 0:
        e = len(text)
    return (s, e)


def _row_structure_signature(line: str) -> str:
    """Return a coarse structural signature for a row-like line."""
    s = str(line or "").strip()
    if not s:
        return ""
    toks = re.findall(r"\S+", s)
    sig: List[str] = []
    for t in toks:
        token = t.strip(" \t\r\n,.;:，。、")
        if t == ">":
            sig.append(">")
        elif "@" in token:
            sig.append("<EML>")
        elif re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", token):
            sig.append("<IP>")
        elif re.fullmatch(r"\d+(?:[-/]\d+)+", token):
            sig.append("<NUMH>")
        elif re.fullmatch(r"\d+", token):
            sig.append("<NUM>")
        elif re.search(r"[A-Za-z가-힣]", token):
            sig.append("<TXT>")
        else:
            sig.append("<ETC>")
    if len(sig) > 24:
        sig = sig[:24]
    return " ".join(sig)


def _token_count(line: str) -> int:
    return len(re.findall(r"\S+", str(line or "")))


def _find_matching_phrase(text: str, phrases: List[str]) -> str:
    s = _normalize_match_text(text)
    if not s or not phrases:
        return ""
    for p in phrases:
        pp = str(p or "").strip()
        if not pp:
            continue
        if _normalize_match_text(pp) in s:
            return pp
    return ""


def _line_index_at(text: str, pos: int) -> int:
    if not text:
        return 0
    p = max(0, min(int(pos), len(text)))
    return text.count("\n", 0, p)


_NAME_PII_ROW_EXCLUDE_TOKENS = {
    "개인정보",
    "고객정보",
    "성명",
    "이름",
    "고객명",
    "담당자",
    "신청자",
    "전화",
    "전화번호",
    "휴대전화",
    "휴대폰",
    "연락처",
    "주민번호",
    "등록번호",
    "여권번호",
    "카드번호",
    "계좌번호",
    "면허번호",
    "운전면허",
    "이메일",
    "메일",
    "주소",
    "관련",
    "안내",
    "안내문",
    "작성",
    "작성해줘",
    "요청",
    "확인",
    "전달",
    "문서",
    "내용",
    "사항",
    "정보",
    "결과",
    "대상",
    "자료",
    "보고서",
    "신청서",
    "우리",
    "부서",
    "내부",
    "정책",
    "마스킹",
    "전송",
    "치환",
    "형태",
    "적용",
    "비식별",
    "익명화",
    "관리",
    "관리번호",
    "문서번호",
    "문서관리",
    "문서관리번호",
    "내부문서",
    "룰라",
    "룰루",
    "랄라",
    "띠로리",
    "부부부부",
}

_KOREAN_COMMON_SINGLE_SYLLABLE_SURNAMES = set(
    "김이박최정강조윤장임한오서신권황안송전홍유고문양손배백허남심노하곽성차주우구민류나진지엄채원천방공현"
)

_KOREAN_EXTENDED_SINGLE_SYLLABLE_SURNAMES = set(
    "함변염여추도석소선설마길연위표명기반왕금옥육인맹제모탁국어은편용예봉사부가승간견경계관교궁궉난당대동두라매빈상섭순시아애영옹음좌초팽피해호"
)

_KOREAN_COMPOUND_SURNAMES = {
    "남궁",
    "황보",
    "제갈",
    "사공",
    "선우",
    "서문",
    "독고",
    "동방",
    "어금",
    "망절",
    "무본",
}

_KOREAN_PARTICLE_LIKE_NAME_ENDINGS = {
    "이",
    "가",
    "은",
    "는",
    "을",
    "를",
    "로",
    "과",
    "와",
    "에",
    "의",
}

_NAME_LABEL_HINT_RE = re.compile(
    r"(?:성\s*명|이\s*름|성함|신청자|고객명|대상자|담당자|수신자|받는\s*사람)\s*[:：]?\s*$"
)

def _is_name_like_korean_token(token: str, *, allow_extended_surname: bool = False, allow_short_given: bool = False) -> bool:
    t = str(token or "").strip()
    if t.endswith("님") and len(t) >= 3:
        t = t[:-1]
    if not re.fullmatch(r"[가-힣]{2,4}", t):
        return False
    if t in _NAME_PII_ROW_EXCLUDE_TOKENS:
        return False
    if any(x in t for x in ("번호", "전화", "계좌", "카드", "여권", "주소", "정보")):
        return False
    # Do not treat arbitrary 2-4 syllable Korean words as names. The row
    # force-pass path is intentionally narrow: common surnames can pass without
    # an explicit label, while extended/rare surnames require a name label.
    if len(t) >= 3 and t[:2] in _KOREAN_COMPOUND_SURNAMES:
        given = t[2:]
    elif t[0] in _KOREAN_COMMON_SINGLE_SYLLABLE_SURNAMES:
        given = t[1:]
    elif allow_extended_surname and t[0] in _KOREAN_EXTENDED_SINGLE_SYLLABLE_SURNAMES:
        given = t[1:]
    else:
        return False
    if not given or len(given) > 2:
        return False
    if len(given) == 1 and not allow_short_given:
        return False
    if len(t) >= 3 and t[-1] in _KOREAN_PARTICLE_LIKE_NAME_ENDINGS:
        return False
    return True


def _has_name_like_token_near_span(line: str, rel_start: int, rel_end: int, max_distance: int) -> Tuple[bool, str]:
    if not line:
        return False, ""
    distance = min(max(0, int(max_distance)), 12)

    start = max(0, int(rel_start) - distance)
    end = max(start, int(rel_start))
    before_nearby = line[start:end]
    for match in re.finditer(r"(?<![가-힣])([가-힣]{2,4}님?)(?![가-힣])", before_nearby):
        token = match.group(0)
        before = before_nearby[:match.start()]
        has_name_label = bool(_NAME_LABEL_HINT_RE.search(before[-24:]))
        if _is_name_like_korean_token(
            token,
            allow_extended_surname=has_name_label,
            allow_short_given=has_name_label,
        ):
            return True, token

    # Also accept the common "PII + name" row shape. Keep the same short
    # distance cap as the left-side scan so generic trailing instructions do
    # not make an unrelated number pass.
    after_start = max(0, int(rel_end))
    after_end = min(len(line), after_start + distance)
    after_nearby = line[after_start:after_end]
    for match in re.finditer(r"(?<![가-힣])([가-힣]{2,4}님?)(?![가-힣])", after_nearby):
        token = match.group(0)
        before = after_nearby[:match.start()]
        has_name_label = bool(_NAME_LABEL_HINT_RE.search(before[-24:]))
        if _is_name_like_korean_token(
            token,
            allow_extended_surname=has_name_label,
            allow_short_given=has_name_label,
        ):
            return True, token
    return False, ""


def _compute_name_pii_row_repeat_plan(
    text: str,
    items: List[dict],
    enabled: bool,
    min_count: int,
    unique_min: int,
    max_distance_chars: int,
    require_consecutive: bool,
) -> Tuple[List[bool], List[int], List[str]]:
    n = len(items or [])
    passes = [False] * n
    counts = [0] * n
    tokens = [""] * n
    if not enabled or n <= 0:
        return passes, counts, tokens

    candidates: List[Tuple[int, int, str]] = []
    for idx, it in enumerate(items or []):
        s = int(it.get("start", 0) or 0)
        e = int(it.get("end", 0) or 0)
        ls, le = _line_bounds(text, s)
        if e > le:
            continue
        line = text[ls:le]
        rel_s = max(0, s - ls)
        rel_e = max(rel_s, e - ls)
        has_name, token = _has_name_like_token_near_span(line, rel_s, rel_e, max_distance_chars)
        if not has_name:
            continue
        line_idx = _line_index_at(text, s)
        candidates.append((idx, line_idx, token))

    if len(candidates) < max(1, int(min_count)):
        return passes, counts, tokens
    unique_values = {
        _normalize_match_text(str((items[idx] or {}).get("matchString") or "").strip())
        for idx, _, _ in candidates
        if _normalize_match_text(str((items[idx] or {}).get("matchString") or "").strip())
    }
    if len(unique_values) < max(1, int(unique_min)):
        return passes, counts, tokens

    min_cnt = max(1, int(min_count))
    if require_consecutive:
        ordered = sorted(candidates, key=lambda x: (x[1], x[0]))
        run: List[Tuple[int, int, str]] = [ordered[0]]
        for cand in ordered[1:]:
            if cand[1] == run[-1][1] + 1:
                run.append(cand)
            else:
                if len(run) >= min_cnt:
                    for idx, _, token in run:
                        passes[idx] = True
                        counts[idx] = len(run)
                        tokens[idx] = token
                run = [cand]
        if len(run) >= min_cnt:
            for idx, _, token in run:
                passes[idx] = True
                counts[idx] = len(run)
                tokens[idx] = token
    else:
        for idx, _, token in candidates:
            passes[idx] = True
            counts[idx] = len(candidates)
            tokens[idx] = token

    return passes, counts, tokens


def _compute_repeat_bonus_plan(
    text: str,
    items: List[dict],
    enabled: bool,
    min_count: int,
    unique_min: int,
    weight: float,
    require_structure: bool,
    structure_min_ratio: float,
    structure_min_count: int,
    structure_min_tokens: int,
    require_consecutive: bool,
    consecutive_min_count: int,
) -> Tuple[List[float], List[float]]:
    n = len(items or [])
    bonuses = [0.0] * n
    ratios = [0.0] * n
    if not enabled or weight <= 0.0 or n <= 0:
        return bonuses, ratios

    repeat_unique_count = len(
        {str(it.get("matchString") or "").strip().lower() for it in items if str(it.get("matchString") or "").strip()}
    )
    if repeat_unique_count < max(1, int(unique_min)):
        return bonuses, ratios

    sig_map: Dict[str, List[Tuple[int, int]]] = {}
    for i, it in enumerate(items):
        s = int(it.get("start", 0))
        ls, le = _line_bounds(text, s)
        line = text[ls:le]
        if _token_count(line) < max(1, int(structure_min_tokens)):
            continue
        sig = _row_structure_signature(line)
        if not sig:
            continue
        line_idx = _line_index_at(text, s)
        sig_map.setdefault(sig, []).append((i, line_idx))

    eligible_total = sum(len(v) for v in sig_map.values())
    if eligible_total <= 0:
        return bonuses, ratios

    min_cnt = max(1, int(min_count))
    consec_cnt = max(1, int(consecutive_min_count))
    for sig, pairs in sig_map.items():
        cnt = len(pairs)
        ratio = float(cnt) / float(eligible_total)
        qualifies = cnt >= min_cnt
        # When consecutive-run gating is enabled, the run condition itself is the
        # primary structure constraint. In that case skip global ratio gating.
        if require_structure and (not require_consecutive):
            qualifies = qualifies and cnt >= max(1, int(structure_min_count)) and ratio >= float(structure_min_ratio)
        if not qualifies:
            continue

        apply_indices: List[int] = []
        if require_consecutive:
            pairs_sorted = sorted(pairs, key=lambda x: x[1])
            run: List[Tuple[int, int]] = [pairs_sorted[0]]
            for p in pairs_sorted[1:]:
                if p[1] == run[-1][1] + 1:
                    run.append(p)
                else:
                    if len(run) >= consec_cnt:
                        apply_indices.extend([x[0] for x in run])
                    run = [p]
            if len(run) >= consec_cnt:
                apply_indices.extend([x[0] for x in run])
        else:
            apply_indices = [x[0] for x in pairs]

        for idx in apply_indices:
            bonuses[idx] = float(weight)
            ratios[idx] = ratio

    return bonuses, ratios


def _normalize_keyword_score(score: int, max_positive: int) -> float:
    """Normalize an integer keyword score to [-1.0, 1.0].

    `score` may be negative (due to non-PII indicators). `max_positive` is the
    number of PII indicator phrases used; we divide by that to get a relative
    score and clamp to [-1,1].
    """
    if max_positive <= 0:
        return 0.0
    val = float(score) / float(max_positive)
    if val > 1.0:
        val = 1.0
    if val < -1.0:
        val = -1.0
    return val


def _normalize_embed_score(diff: float) -> float:
    """Normalize embedding-based score (max_sim - non_sim) to [-1.0, 1.0].

    Since sims are cosine in [-1,1], the diff is in [-2,2]; divide by 2.
    """
    val = float(diff) / 2.0
    if val > 1.0:
        val = 1.0
    if val < -1.0:
        val = -1.0
    return val


def _match_value_counts(items: List[dict]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for it in items or []:
        key = _normalize_match_text(str(it.get("matchString") or "").strip())
        if not key:
            continue
        counts[key] = counts.get(key, 0) + 1
    return counts


def _digit_ratio(s: str) -> float:
    if not s:
        return 0.0
    digits = sum(1 for ch in s if ch.isdigit())
    return float(digits) / float(len(s))


def _rule_context_score(
    text: str,
    start: int,
    end: int,
    match_str: str,
    label_res: List[Pattern],
    label_window: int,
    label_weight: float,
    digit_min_ratio: float,
    digit_weight: float,
    header_hint: str = "",
    header_weight: float = 0.0,
    label_direction: str = "both",
) -> float:
    score = 0.0
    if label_res:
        w = max(0, int(label_window))
        direction = str(label_direction or "both").strip().lower()
        if direction == "before":
            s = max(0, start - w)
            e = start
        elif direction == "after":
            s = end
            e = min(len(text), end + w)
        else:
            s = max(0, start - w)
            e = min(len(text), end + w)
        window = text[s:e]
        if any(rx.search(window) for rx in label_res):
            score += float(label_weight)
        if header_hint and any(rx.search(header_hint) for rx in label_res):
            score += float(header_weight if header_weight > 0 else label_weight)

    if digit_weight:
        if _digit_ratio(match_str) >= float(digit_min_ratio):
            score += float(digit_weight)

    return score


__all__ = [name for name in globals() if not name.startswith("__")]


