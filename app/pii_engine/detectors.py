from __future__ import annotations

import base64
import binascii
import unicodedata

from .common import *
from ..sensitive_values import (
    PHASE1_SENSITIVE_TYPES,
    SensitivePatternSet,
    build_sensitive_scan_view,
    phase1_sensitive_syntax_possible,
)


def _typed_structure_valid(out_key: str, text: str, item: dict) -> bool:
    """Apply the same type-specific validation regardless of scan backend."""
    value = str(item.get("matchString", ""))
    if out_key == "EML":
        return email_structure_valid(value)
    if out_key == "SSN":
        return ssn_structure_valid(value) and not ssn_candidate_in_non_pii_url(
            text,
            int(item.get("start", 0)),
            int(item.get("end", 0)),
        )
    if out_key == "CN":
        return card_structure_valid(value)
    if out_key == "CPN":
        return cpn_structure_valid(value)
    if out_key == "CRN":
        return crn_structure_valid(value)
    if out_key == "IMEI":
        return imei_structure_valid(value)
    if out_key == "MCN":
        return mac_structure_valid(value)
    if out_key == "IP":
        return ip_structure_valid(value)
    return True


class DNDetector(Detector):
    def __init__(self, hs_db: HyperscanDB, enabled: bool = True):
        self.hs_db = hs_db
        self.enabled = enabled

    def run(self, ctx: DetectContext) -> None:
        if not self.enabled:
            ctx.set("DN", [])
            return
        t0 = _timing_now()
        results = self.hs_db.detect(ctx.text)
        detect_ms = _timing_ms(t0)
        t1 = _timing_now()
        existing = ctx.get("DN") or []
        merged = _finalize(existing + results)
        ctx.set("DN", merged[:ctx.max_results])
        _log_timing("dn.hyperscan", req_id=ctx.request_id, scan_ms=f"{detect_ms:.1f}", finalize_ms=f"{_timing_ms(t1):.1f}", matches=len(results))


class HSRegexDetector(Detector):
    """Hyperscan-first detector with optional Python verify-regex guard."""

    def __init__(
        self,
        out_key: str,
        hs_db: HyperscanDB,
        enabled: bool,
        max_match_len: int,
        verify_regexes: List[Pattern] | None = None,
        verify_window_chars: int = 2,
        supplement_regexes: List[Pattern] | None = None,
    ):
        self.out_key = out_key
        self.hs_db = hs_db
        self.enabled = enabled
        self.max_match_len = int(max_match_len)
        self.verify_regexes = verify_regexes or []
        self.verify_window_chars = max(0, int(verify_window_chars))
        self.supplement_regexes = supplement_regexes or []

    def _scan_raw(self, ctx: DetectContext) -> Tuple[List[dict], float, bool]:
        if hasattr(self.hs_db, "detect_all"):
            cache_key = f"hs_combined:{id(self.hs_db)}"
            bucketed = ctx.get_extra(cache_key)
            if bucketed is None:
                t0 = _timing_now()
                bucketed = self.hs_db.detect_all(ctx.text)
                scan_ms = _timing_ms(t0)
                ctx.set_extra(cache_key, bucketed)
                _log_timing(
                    "hs.combined",
                    req_id=ctx.request_id,
                    ms=f"{scan_ms:.1f}",
                    patterns=getattr(self.hs_db, "pattern_count", 0),
                    buckets=len(bucketed),
                )
            raw = bucketed.get(self.out_key, [])
            return raw, 0.0, True
        t0 = _timing_now()
        return self.hs_db.detect(ctx.text), _timing_ms(t0), False

    def _verify(self, text: str, it: dict) -> bool:
        if not self.verify_regexes:
            return True
        pid = it.get("_hs_id")
        if not isinstance(pid, int) or pid < 0 or pid >= len(self.verify_regexes):
            return True
        vr = self.verify_regexes[pid]
        s = int(it.get("start", 0))
        e = int(it.get("end", 0))
        ws = max(0, s - self.verify_window_chars)
        we = min(len(text), e + self.verify_window_chars)
        win = text[ws:we]
        rel_s = s - ws
        rel_e = e - ws
        for m in vr.finditer(win):
            if m.start() == rel_s and m.end() == rel_e:
                return True
        return False

    def _recover_verified_span(self, text: str, it: dict) -> Tuple[int, int] | None:
        """Recover accurate span when Hyperscan start offset is unreliable.

        Strategy:
        - Use the candidate end offset as anchor.
        - Search verify-regex in a small window around the end.
        - Prefer matches ending at the same char offset.
        """
        if not self.verify_regexes:
            return None
        pid = it.get("_hs_id")
        if not isinstance(pid, int) or pid < 0 or pid >= len(self.verify_regexes):
            return None
        vr = self.verify_regexes[pid]
        e = int(it.get("end", 0))
        if e <= 0:
            return None
        ws = max(0, e - max(self.max_match_len + 8, 32))
        we = min(len(text), e + self.verify_window_chars + 2)
        win = text[ws:we]
        best = None
        for m in vr.finditer(win):
            abs_s = ws + m.start()
            abs_e = ws + m.end()
            if abs_e == e:
                return (abs_s, abs_e)
            # nearest-by-end fallback
            dist = abs(abs_e - e)
            cand = (dist, abs_s, abs_e)
            if best is None or cand < best:
                best = cand
        if best is not None and best[0] <= 2:
            return (best[1], best[2])
        return None

    def _scan_supplement(self, ctx: DetectContext) -> List[dict]:
        if not self.supplement_regexes:
            return []
        return _scan_regex_cursor(
            ctx.text,
            self.supplement_regexes,
            max_results=ctx.max_results,
            max_len=self.max_match_len,
        )

    def run(self, ctx: DetectContext) -> None:
        if not self.enabled:
            ctx.set(self.out_key, [])
            return
        if self.out_key == "EML" and "@" not in ctx.text:
            ctx.set(self.out_key, [])
            _log_timing(
                "eml.hyperscan",
                req_id=ctx.request_id,
                scan_ms="0.0",
                verify_ms="0.0",
                finalize_ms="0.0",
                raw_matches=0,
                kept=0,
                shared_scan=0,
                skipped=1,
            )
            return
        raw, scan_ms, shared_scan = self._scan_raw(ctx)
        t0_verify = _timing_now()
        out: List[dict] = []
        for it in raw:
            s = int(it.get("start", 0))
            e = int(it.get("end", 0))
            if e <= s:
                continue
            if not self._verify(ctx.text, it):
                rec = self._recover_verified_span(ctx.text, it)
                if rec is None:
                    continue
                s, e = rec
                if e <= s:
                    continue
            if (e - s) > self.max_match_len:
                continue
            candidate = {"start": s, "end": e, "matchString": ctx.text[s:e]}
            if not _typed_structure_valid(self.out_key, ctx.text, candidate):
                continue
            out.append(candidate)
            if len(out) >= ctx.max_results:
                break
        if self.supplement_regexes and len(out) < ctx.max_results:
            out.extend(self._scan_supplement(ctx))
        out = [it for it in out if _typed_structure_valid(self.out_key, ctx.text, it)]
        verify_ms = _timing_ms(t0_verify)
        t0_finalize = _timing_now()
        existing = ctx.get(self.out_key) or []
        ctx.set(self.out_key, _finalize(existing + out))
        _log_timing(
            f"{self.out_key.lower()}.hyperscan",
            req_id=ctx.request_id,
            scan_ms=f"{scan_ms:.1f}",
            verify_ms=f"{verify_ms:.1f}",
            finalize_ms=f"{_timing_ms(t0_finalize):.1f}",
            raw_matches=len(raw),
            kept=len(out),
            shared_scan=int(shared_scan),
        )


# ============================================================
# Regex detectors
# ============================================================


class RegexDetector(Detector):
    def __init__(
        self,
        out_key: str,
        regexes: List[Pattern],
        enabled: bool,
        max_match_len: int,
        split_newlines: bool = False,
    ):
        self.out_key = out_key
        self.regexes = regexes
        self.enabled = enabled
        self.max_match_len = max_match_len
        self.split_newlines = split_newlines

    def run(self, ctx: DetectContext) -> None:
        if not self.enabled:
            ctx.set(self.out_key, [])
            return
        t0_scan = _timing_now()
        items = _scan_regex_cursor(ctx.text, self.regexes, max_results=ctx.max_results, max_len=self.max_match_len)
        scan_ms = _timing_ms(t0_scan)
        t0_post = _timing_now()
        if self.split_newlines:
            split_items: List[dict] = []
            for it in items:
                s = int(it.get("start", 0))
                e = int(it.get("end", 0))
                raw = str(it.get("matchString", ""))
                if "\n" not in raw:
                    split_items.append(it)
                    continue
                rel = 0
                for part in raw.splitlines():
                    part = part.strip()
                    if not part:
                        rel += 1
                        continue
                    idx = raw.find(part, rel)
                    if idx < 0:
                        continue
                    ps = s + idx
                    pe = ps + len(part)
                    if pe <= e:
                        split_items.append({"start": ps, "end": pe, "matchString": ctx.text[ps:pe]})
                    rel = idx + len(part)
            items = split_items
        if self.out_key == "AN":
            cleaned: List[dict] = []
            for it in items:
                ms = str(it.get("matchString", ""))
                trimmed = _trim_an_suffix(ms)
                if not trimmed:
                    continue
                if len(trimmed) < 8:
                    continue
                s = int(it.get("start", 0))
                e = s + len(trimmed)
                if e <= s:
                    continue
                cleaned.append({"start": s, "end": e, "matchString": ctx.text[s:e]})
            items = cleaned
        else:
            items = [it for it in items if _typed_structure_valid(self.out_key, ctx.text, it)]
        post_ms = _timing_ms(t0_post)
        t0_finalize = _timing_now()
        existing = ctx.get(self.out_key) or []
        ctx.set(self.out_key, _finalize(existing + items))
        _log_timing(
            f"{self.out_key.lower()}.regex",
            req_id=ctx.request_id,
            scan_ms=f"{scan_ms:.1f}",
            post_ms=f"{post_ms:.1f}",
            finalize_ms=f"{_timing_ms(t0_finalize):.1f}",
            matches=len(items),
        )


class SensitiveValueDetector(Detector):
    """Detect a sensitive value captured by a named regex group."""

    def __init__(self, out_key: str, rule_doc: Dict[str, Any]):
        self.out_key = str(out_key).upper()
        self.pattern_set = SensitivePatternSet(self.out_key, rule_doc)

    def run(self, ctx: DetectContext) -> None:
        t0 = _timing_now()
        scan_view = ctx.get_extra("sensitive_scan_view")
        if scan_view is None:
            scan_view = build_sensitive_scan_view(ctx.text) or False
            ctx.set_extra("sensitive_scan_view", scan_view)
        lowered = ctx.get_extra("sensitive_lowered_text")
        if lowered is None:
            lowered = ctx.text.lower()
            ctx.set_extra("sensitive_lowered_text", lowered)
        if self.out_key in PHASE1_SENSITIVE_TYPES:
            phase1_possible = ctx.get_extra("phase1_sensitive_syntax_possible")
            if phase1_possible is None:
                phase1_possible = phase1_sensitive_syntax_possible(ctx.text, lowered) or bool(
                    scan_view and phase1_sensitive_syntax_possible(scan_view.text, scan_view.text.lower())
                )
                ctx.set_extra("phase1_sensitive_syntax_possible", phase1_possible)
            if not phase1_possible:
                ctx.set(self.out_key, ctx.get(self.out_key) or [])
                _log_timing(
                    f"{self.out_key.lower()}.sensitive",
                    req_id=ctx.request_id,
                    ms=f"{_timing_ms(t0):.1f}",
                    matches=0,
                    prefilter_skip=1,
                )
                return
        items = self.pattern_set.find(
            ctx.text,
            max_results=ctx.max_results,
            lowered_text=lowered,
            scan_view=scan_view if scan_view else None,
        )
        existing = ctx.get(self.out_key) or []
        ctx.set(self.out_key, _finalize(existing + items))
        _log_timing(
            f"{self.out_key.lower()}.sensitive",
            req_id=ctx.request_id,
            ms=f"{_timing_ms(t0):.1f}",
            matches=len(items),
        )


class SNDetector(Detector):
    def __init__(self, regexes: List[Pattern], enabled: bool, max_match_len: int, checksum_enabled: bool):
        self.regexes = regexes
        self.enabled = enabled
        self.max_match_len = max_match_len
        self.checksum_enabled = checksum_enabled

    def run(self, ctx: DetectContext) -> None:
        if not self.enabled:
            ctx.set("SN", [])
            return

        t0_scan = _timing_now()
        raw = _scan_regex_cursor(ctx.text, self.regexes, max_results=ctx.max_results, max_len=self.max_match_len)
        raw = _finalize(raw)
        scan_ms = _timing_ms(t0_scan)

        if not self.checksum_enabled:
            sn_raw = [it for it in raw if not rrn_foreigner_registration_candidate(it.get("matchString") or "")]
            fn_raw = [it for it in raw if rrn_foreigner_registration_candidate(it.get("matchString") or "")]
            existing_sn = ctx.get("SN") or []
            existing_fn = ctx.get("FN") or []
            ctx.set("SN", _finalize(existing_sn + sn_raw))
            ctx.set("FN", _finalize(existing_fn + fn_raw))
            _log_timing("sn.regex", req_id=ctx.request_id, scan_ms=f"{scan_ms:.1f}", checksum_ms="0.0", valid=len(sn_raw), fn_valid=len(fn_raw), invalid=0)
            return

        t0_checksum = _timing_now()
        sn_valid: List[dict] = []
        fn_valid: List[dict] = []

        for it in raw:
            checksum_status = rrn_checksum_policy_status(it["matchString"])
            if checksum_status != "checksum_fail":
                it["isValid"] = True
                it["checksum_status"] = checksum_status
                if rrn_foreigner_registration_candidate(it["matchString"]):
                    fn_valid.append(it)
                else:
                    sn_valid.append(it)

        existing_sn = ctx.get("SN") or []
        existing_fn = ctx.get("FN") or []
        ctx.set("SN", _finalize(existing_sn + sn_valid))
        ctx.set("FN", _finalize(existing_fn + fn_valid))
        _log_timing(
            "sn.regex",
            req_id=ctx.request_id,
            scan_ms=f"{scan_ms:.1f}",
            checksum_ms=f"{_timing_ms(t0_checksum):.1f}",
            valid=len(sn_valid),
            fn_valid=len(fn_valid),
            invalid=0,
        )


class SNHSDetector(HSRegexDetector):
    """SN detector using Hyperscan candidate scan + checksum split."""

    def __init__(
        self,
        hs_db: HyperscanDB,
        enabled: bool,
        max_match_len: int,
        checksum_enabled: bool,
        verify_regexes: List[Pattern] | None = None,
        verify_window_chars: int = 1,
        supplement_regexes: List[Pattern] | None = None,
    ):
        super().__init__(
            out_key="SN",
            hs_db=hs_db,
            enabled=enabled,
            max_match_len=max_match_len,
            verify_regexes=verify_regexes,
            verify_window_chars=verify_window_chars,
            supplement_regexes=supplement_regexes,
        )
        self.checksum_enabled = checksum_enabled

    def run(self, ctx: DetectContext) -> None:
        if not self.enabled:
            ctx.set("SN", [])
            return

        raw, scan_ms, shared_scan = self._scan_raw(ctx)
        t0_verify = _timing_now()
        candidates: List[dict] = []
        for it in raw:
            s = int(it.get("start", 0))
            e = int(it.get("end", 0))
            if e <= s:
                continue
            if not self._verify(ctx.text, it):
                rec = self._recover_verified_span(ctx.text, it)
                if rec is None:
                    continue
                s, e = rec
                if e <= s:
                    continue
            if (e - s) > self.max_match_len:
                continue
            candidates.append({"start": s, "end": e, "matchString": ctx.text[s:e]})
            if len(candidates) >= ctx.max_results:
                break
        if self.supplement_regexes and len(candidates) < ctx.max_results:
            candidates.extend(self._scan_supplement(ctx))
        candidates = _finalize(candidates)
        verify_ms = _timing_ms(t0_verify)

        if not self.checksum_enabled:
            sn_raw = [it for it in candidates if not rrn_foreigner_registration_candidate(it.get("matchString") or "")]
            fn_raw = [it for it in candidates if rrn_foreigner_registration_candidate(it.get("matchString") or "")]
            existing_sn = ctx.get("SN") or []
            existing_fn = ctx.get("FN") or []
            ctx.set("SN", _finalize(existing_sn + sn_raw))
            ctx.set("FN", _finalize(existing_fn + fn_raw))
            _log_timing("sn.hyperscan", req_id=ctx.request_id, scan_ms=f"{scan_ms:.1f}", verify_ms=f"{verify_ms:.1f}", checksum_ms="0.0", valid=len(sn_raw), fn_valid=len(fn_raw), invalid=0, shared_scan=int(shared_scan))
            return

        t0_checksum = _timing_now()
        sn_valid: List[dict] = []
        fn_valid: List[dict] = []
        for it in candidates:
            checksum_status = rrn_checksum_policy_status(it["matchString"])
            if checksum_status != "checksum_fail":
                it["isValid"] = True
                it["checksum_status"] = checksum_status
                if rrn_foreigner_registration_candidate(it["matchString"]):
                    fn_valid.append(it)
                else:
                    sn_valid.append(it)

        existing_sn = ctx.get("SN") or []
        existing_fn = ctx.get("FN") or []
        ctx.set("SN", _finalize(existing_sn + sn_valid))
        ctx.set("FN", _finalize(existing_fn + fn_valid))
        _log_timing(
            "sn.hyperscan",
            req_id=ctx.request_id,
            scan_ms=f"{scan_ms:.1f}",
            verify_ms=f"{verify_ms:.1f}",
            checksum_ms=f"{_timing_ms(t0_checksum):.1f}",
            valid=len(sn_valid),
            fn_valid=len(fn_valid),
            invalid=0,
            shared_scan=int(shared_scan),
        )


class BRNDetector(Detector):
    def __init__(self, regexes: List[Pattern], enabled: bool, max_match_len: int, checksum_enabled: bool):
        self.regexes = regexes
        self.enabled = enabled
        self.max_match_len = max_match_len
        self.checksum_enabled = checksum_enabled

    def run(self, ctx: DetectContext) -> None:
        if not self.enabled:
            ctx.set("BRN", [])
            return

        t0_scan = _timing_now()
        raw = _scan_regex_cursor(ctx.text, self.regexes, max_results=ctx.max_results, max_len=self.max_match_len)
        raw = _finalize(raw)
        scan_ms = _timing_ms(t0_scan)

        t0_checksum = _timing_now()
        valid: List[dict] = []
        for it in raw:
            if self.checksum_enabled and not brn_structure_valid(it["matchString"]):
                continue
            it["isValid"] = True
            it["checksum_status"] = "checksum_pass" if self.checksum_enabled else "checksum_skipped"
            valid.append(it)

        existing = ctx.get("BRN") or []
        ctx.set("BRN", _finalize(existing + valid))
        _log_timing(
            "brn.regex",
            req_id=ctx.request_id,
            scan_ms=f"{scan_ms:.1f}",
            checksum_ms=f"{_timing_ms(t0_checksum):.1f}",
            valid=len(valid),
            invalid=max(0, len(raw) - len(valid)),
        )


class ANHSDetector(HSRegexDetector):
    """AN detector using Hyperscan candidate scan + AN-specific cleanup."""

    def run(self, ctx: DetectContext) -> None:
        if not self.enabled:
            ctx.set("AN", [])
            return

        raw, scan_ms, shared_scan = self._scan_raw(ctx)
        t0_verify = _timing_now()
        out: List[dict] = []
        for it in raw:
            s = int(it.get("start", 0))
            e = int(it.get("end", 0))
            if e <= s:
                continue
            if not self._verify(ctx.text, it):
                rec = self._recover_verified_span(ctx.text, it)
                if rec is None:
                    continue
                s, e = rec
                if e <= s:
                    continue
            if (e - s) > self.max_match_len:
                continue
            out.append({"start": s, "end": e, "matchString": ctx.text[s:e]})
            if len(out) >= ctx.max_results:
                break
        if self.supplement_regexes and len(out) < ctx.max_results:
            out.extend(self._scan_supplement(ctx))

        verify_ms = _timing_ms(t0_verify)
        t0_clean = _timing_now()
        cleaned: List[dict] = []
        for it in _finalize(out):
            ms = str(it.get("matchString", ""))
            trimmed = _trim_an_suffix(ms)
            if not trimmed:
                continue
            if len(trimmed) < 8:
                continue
            s = int(it.get("start", 0))
            e = s + len(trimmed)
            if e <= s:
                continue
            cleaned.append({"start": s, "end": e, "matchString": ctx.text[s:e]})

        existing = ctx.get("AN") or []
        ctx.set("AN", _finalize(existing + cleaned))
        _log_timing(
            "an.hyperscan",
            req_id=ctx.request_id,
            scan_ms=f"{scan_ms:.1f}",
            verify_ms=f"{verify_ms:.1f}",
            clean_ms=f"{_timing_ms(t0_clean):.1f}",
            raw_matches=len(raw),
            kept=len(cleaned),
            shared_scan=int(shared_scan),
        )


# ============================================================
# Post filters (MN/BN)
# ============================================================


_VN_MOBILE_PREFIXES = {
    "032", "033", "034", "035", "036", "037", "038", "039",
    "052", "055", "056", "058", "059", "070", "076", "077",
    "078", "079", "081", "082", "083", "084", "085", "086",
    "087", "088", "089", "090", "091", "092", "093", "094",
    "096", "097", "098", "099",
}

_VN_CCCD_PROVINCE_CODES = {
    "001", "002", "004", "006", "008", "010", "011", "012",
    "014", "015", "017", "019", "020", "022", "024", "025",
    "026", "027", "030", "031", "033", "034", "035", "036",
    "037", "038", "040", "042", "044", "045", "046", "048",
    "049", "051", "052", "054", "056", "058", "060", "062",
    "064", "066", "067", "068", "070", "072", "074", "075",
    "077", "079", "080", "082", "083", "084", "086", "087",
    "089", "091", "092", "093", "094", "095", "096",
}


class NumericAlternateSeparatorDetector(Detector):
    """PoC recall-first detector for numeric identifiers using punctuation.

    Any configured non-standard separator may occur between digit groups and
    mixed separators are accepted. Type-specific checksums and structural
    validation still decide which candidate buckets receive the token.
    """

    def __init__(self, config: Dict[str, Any] | None):
        cfg = config if isinstance(config, dict) else {}
        self.enabled = bool(cfg.get("enabled", False))
        self.min_digits = max(1, int(cfg.get("min_digits", 9)))
        self.max_digits = max(self.min_digits, int(cfg.get("max_digits", 16)))
        self.label_window_chars = max(0, int(cfg.get("label_window_chars", 48)))
        self.separator_chars = str(cfg.get("separator_chars") or "")
        self.labels = {
            str(out_key).upper(): tuple(
                str(label).casefold()
                for label in labels
                if isinstance(label, str) and str(label).strip()
            )
            for out_key, labels in (cfg.get("labels") or {}).items()
            if isinstance(labels, list)
        }
        self.token_re: Pattern | None = None
        if self.enabled and self.separator_chars:
            separators = re.escape(self.separator_chars)
            self.token_re = re.compile(
                rf"(?<!\d)\d+(?:[ \t]*[{separators}][ \t]*\d+)+(?!\d)"
            )
        else:
            self.enabled = False

    def _nearest_label_types(self, text: str, start: int) -> set[str]:
        if not self.labels or self.label_window_chars <= 0:
            return set()
        snippet = text[max(0, start - self.label_window_chars):start].casefold()
        best_position = -1
        best_types: set[str] = set()
        for out_key, labels in self.labels.items():
            for label in labels:
                position = snippet.rfind(label)
                if position < 0:
                    continue
                if position > best_position:
                    best_position = position
                    best_types = {out_key}
                elif position == best_position:
                    best_types.add(out_key)
        return best_types

    @staticmethod
    def _kr_phone_valid(digits: str) -> bool:
        if len(digits) == 11 and digits[:4] in {"0100", "0101"}:
            return False
        return bool(
            re.fullmatch(r"0(?:10|11|16|17|18|19)\d{7,8}", digits)
            or re.fullmatch(r"02\d{7,8}", digits)
            or re.fullmatch(r"0[3-9]\d\d{7,8}", digits)
        )

    def _append(
        self,
        buckets: Dict[str, List[dict]],
        out_key: str,
        base_item: dict,
        label_types: set[str],
        **metadata: Any,
    ) -> None:
        if label_types and out_key not in label_types:
            # An explicit nearby label is stronger than ambiguous digit length.
            # This also prevents a list delimiter from joining two labeled
            # phone numbers into one broad BN candidate.
            return
        item = dict(base_item)
        item.update(metadata)
        item["detected_by"] = f"numeric_alternate_separator:{out_key.lower()}"
        if out_key in label_types:
            item["context_pass"] = True
            item["context_accept_by"] = "explicit_numeric_label"
        buckets.setdefault(out_key, []).append(item)

    def _classify(self, ctx: DetectContext, buckets: Dict[str, List[dict]], start: int, end: int) -> bool:
        raw = ctx.text[start:end]
        digits = _digits_only(raw)
        if not (self.min_digits <= len(digits) <= self.max_digits):
            return False
        if len(set(digits)) <= 1:
            return False

        base_item = {"start": start, "end": end, "matchString": raw}
        label_types = self._nearest_label_types(ctx.text, start)

        if len(digits) == 13:
            checksum_status = rrn_checksum_policy_status(raw)
            if checksum_status != "checksum_fail":
                rrn_key = "FN" if rrn_foreigner_registration_candidate(raw) else "SN"
                self._append(
                    buckets,
                    rrn_key,
                    base_item,
                    label_types,
                    isValid=True,
                    checksum_status=checksum_status,
                )

        if len(digits) == 9 and ssn_structure_valid(raw) and not ssn_candidate_in_non_pii_url(ctx.text, start, end):
            self._append(buckets, "SSN", base_item, label_types)

        if len(digits) == 12 and digits != "0" * 12:
            self._append(buckets, "DN", base_item, label_types)

        if self._kr_phone_valid(digits) and phone_structure_valid(raw):
            self._append(buckets, "MN", base_item, label_types)

        if len(digits) == 10 and digits[:3] in _VN_MOBILE_PREFIXES:
            self._append(buckets, "VN_MN", base_item, label_types)

        if brn_structure_valid(raw):
            self._append(
                buckets,
                "BRN",
                base_item,
                label_types,
                isValid=True,
                checksum_status="checksum_pass",
            )

        if 10 <= len(digits) <= 16:
            self._append(buckets, "BN", base_item, label_types)

        if card_structure_valid(raw):
            self._append(buckets, "CN", base_item, label_types)

        if cpn_structure_valid(raw):
            self._append(buckets, "CPN", base_item, label_types)

        if imei_structure_valid(raw):
            self._append(buckets, "IMEI", base_item, label_types)

        if len(digits) == 12 and digits[:3] in _VN_CCCD_PROVINCE_CODES:
            self._append(buckets, "VN_CCCD", base_item, label_types)

        if len(digits) in {10, 13}:
            self._append(buckets, "VN_TIN", base_item, label_types)

        if len(digits) == 10:
            self._append(buckets, "VN_SI", base_item, label_types)
        return True

    def _candidate_spans(self, matched: re.Match) -> List[Tuple[int, int]]:
        spans = [matched.span()]
        raw = matched.group(0)
        separators = re.escape(self.separator_chars)
        split_re = re.compile(rf"[ \t]+[{separators}][ \t]+")
        cursor = 0
        split_found = False
        for separator_match in split_re.finditer(raw):
            split_found = True
            if separator_match.start() > cursor:
                spans.append((matched.start() + cursor, matched.start() + separator_match.start()))
            cursor = separator_match.end()
        if split_found and cursor < len(raw):
            spans.append((matched.start() + cursor, matched.end()))
        return spans

    def run(self, ctx: DetectContext) -> None:
        if not self.enabled or self.token_re is None:
            return

        buckets: Dict[str, List[dict]] = {}
        candidate_count = 0
        seen_spans: set[Tuple[int, int]] = set()
        stop = False
        for matched in self.token_re.finditer(ctx.text):
            for start, end in self._candidate_spans(matched):
                if (start, end) in seen_spans:
                    continue
                seen_spans.add((start, end))
                if not self._classify(ctx, buckets, start, end):
                    continue
                candidate_count += 1
                if candidate_count >= ctx.max_results:
                    stop = True
                    break
            if stop:
                break

        for out_key, items in buckets.items():
            ctx.set(out_key, _finalize(ctx.get(out_key) + items))

        _log_timing(
            "numeric_alternate_separator",
            req_id=ctx.request_id,
            candidates=candidate_count,
            typed_matches=sum(len(items) for items in buckets.values()),
        )


class EvasionRecoveryDetector(Detector):
    """Recover a bounded set of high-confidence obfuscations.

    This intentionally runs after context filtering.  Expensive transforms are
    gated by explicit words such as ``decode`` or ``reverse`` and every
    recovered value must still satisfy a type-specific structural check.
    """

    _RRN_LABEL_RE = re.compile(
        r"주민\s*(?:등록\s*)?번호|외국인\s*(?:등록\s*)?번호|생년월일|뒷자리|"
        r"앞\s*6|뒤\s*7|jumin|resident\s+registration|birth|serial|front|back",
        re.IGNORECASE,
    )
    _PHONE_LABEL_RE = re.compile(r"전화\s*번호|연락처|휴대\s*(?:폰|전화)|phone|mobile", re.IGNORECASE)
    _TRANSFORM_HINT_RE = re.compile(r"base\s*64|디코(?:딩|드)|decode|복호", re.IGNORECASE)
    _REVERSE_HINT_RE = re.compile(r"뒤집|역순|reverse", re.IGNORECASE)
    _KEY_HINT_RE = re.compile(r"(?:api|access)?\s*key|키|token|토큰", re.IGNORECASE)
    _RRN_DIRECT_RE = re.compile(
        r"(?<!\d)\d{6}[ \t]*(?:_|[\u2010-\u2015\u2212\uff0d\uff5e]|%2[dD])[ \t]*\d{7}(?!\d)"
    )
    _RRN_CONTEXT_SEPARATOR_RE = re.compile(
        r"(?<!\d)\d{6}[ \t]*(?:[~:,#]|-{2})[ \t]*\d{7}(?!\d)"
    )
    _RRN_CONTEXT_SPACED_RE = re.compile(
        r"(?<!\d)\d(?:[ \t\u00a0\u3000]*\d){12}(?!\d)"
    )
    _RRN_CANONICAL_RE = re.compile(r"(?<!\d)\d{6}-\d{7}(?!\d)")
    _CARD_CANONICAL_RE = re.compile(r"(?<!\d)\d{4}(?:[- ]\d{4}){3}(?!\d)")
    _DN_CANONICAL_RE = re.compile(r"(?<!\d)\d{2}-\d{2}-\d{6}-\d{2}(?!\d)")
    _PHONE_SPECIAL_RE = re.compile(
        r"(?<!\d)(?:82\)\s*10[-. ]?\d{3,4}[-. ]?\d{4}|\(010\)\s*\d{3,4}[-. ]?\d{4})(?!\d)"
    )
    _AWS_FRAGMENT_RE = re.compile(
        r"(?<![A-Z0-9])(?:(?:AKIA|ASIA)[A-Z0-9]{1,15}(?:[ \t\r\n]+[A-Z0-9]+)+|"
        r"(?:A\s*K\s*I\s*A|A\s*S\s*I\s*A)(?:[ \t\r\n]+[A-Z0-9]+){1,20})(?![A-Z0-9])",
        re.IGNORECASE,
    )
    _GITHUB_FRAGMENT_RE = re.compile(r"(?<![A-Za-z0-9])gh[oprsu]_[A-Za-z0-9-]{36,80}(?![A-Za-z0-9])")
    _BASE64_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/]{16,252}={0,2}(?![A-Za-z0-9+/=_-])")
    _REVERSE_TOKEN_RE = re.compile(r"(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])", re.IGNORECASE)
    _CONFUSABLE_EMAIL_RE = re.compile(r"(?<![\w.+-])[\w.+-]{1,64}@[\w.-]{3,253}\.[A-Za-z\u0400-\u04ff]{2,24}(?![\w.-])")
    _HANGUL_DIGIT_RE = re.compile(r"(?:공|영|일|이|삼|사|오|육|륙|칠|팔|구)(?:\s*(?:공|영|일|이|삼|사|오|육|륙|칠|팔|구)){12}")
    _SPLIT_RRN_PATTERNS = (
        re.compile(r"(?:앞\s*6자리는|생년월일|front|birth)[^\d]{0,30}(\d{6})[\s\S]{0,80}?(?:뒤\s*7자리는|뒷자리|back|serial)[^\d]{0,30}(\d{7})", re.IGNORECASE),
        re.compile(r"(?:jumin\s*=\s*)?[\"'](\d{6})[\"']\s*\+\s*[\"']-?[\"']\s*\+\s*[\"'](\d{7})[\"']", re.IGNORECASE),
        re.compile(r"(?:front|birth)\s*=\s*[\"'](\d{6})[\"'][\s\S]{0,100}?(?:back|serial)\s*=\s*[\"'](\d{7})[\"']", re.IGNORECASE),
        re.compile(r"[\"'](?:birth|front)[\"']\s*:\s*[\"'](\d{6})[\"'][\s\S]{0,60}?[\"'](?:serial|back)[\"']\s*:\s*[\"'](\d{7})[\"']", re.IGNORECASE),
        re.compile(r"(\d{6})-([1-8])\*{4,8}[\s\S]{0,80}?(?:뒤\s*6자리|suffix|나머지)[^\d]{0,20}(\d{6})", re.IGNORECASE),
    )
    _HANGUL_DIGITS = str.maketrans({"공": "0", "영": "0", "일": "1", "이": "2", "삼": "3", "사": "4", "오": "5", "육": "6", "륙": "6", "칠": "7", "팔": "8", "구": "9"})
    _CYRILLIC_SKELETON = str.maketrans({
        "а": "a", "А": "A", "е": "e", "Е": "E", "о": "o", "О": "O",
        "р": "p", "Р": "P", "с": "c", "С": "C", "х": "x", "Х": "X",
        "у": "y", "У": "Y", "к": "k", "К": "K", "м": "m", "М": "M",
        "т": "t", "Т": "T", "в": "b", "В": "B", "н": "h", "Н": "H",
    })

    def __init__(self, config: Dict[str, Any] | None):
        cfg = config if isinstance(config, dict) else {}
        self.enabled = bool(cfg.get("enabled", True))
        self.max_transform_candidates = max(1, int(cfg.get("max_transform_candidates", 32)))
        self.max_split_span = max(32, int(cfg.get("max_split_span", 180)))

    @staticmethod
    def _add(ctx: DetectContext, out_key: str, start: int, end: int, method: str, **metadata: Any) -> None:
        raw = ctx.text[start:end]
        item = {
            "start": start,
            "end": end,
            "matchString": raw,
            "detected_by": f"evasion_recovery:{method}",
            "context_pass": True,
            "context_accept_by": f"evasion_recovery:{method}",
        }
        item.update(metadata)
        ctx.set(out_key, _finalize((ctx.get(out_key) or []) + [item])[:ctx.max_results])

    @staticmethod
    def _rrn_type(value: str) -> tuple[str, str] | None:
        status = rrn_checksum_policy_status(value)
        if not rrn_structure_valid(value) or status == "checksum_fail":
            return None
        return ("FN" if rrn_foreigner_registration_candidate(value) else "SN", status)

    @staticmethod
    def _is_whole_value(text: str, start: int, end: int) -> bool:
        return not text[:start].strip() and not text[end:].strip()

    @staticmethod
    def _has_table_or_list_action(text: str) -> bool:
        if "표" not in text and "명단" not in text:
            return False
        return bool(re.search(r"(?:표|명단)(?:\s*로)?\s*정리", text))

    @staticmethod
    def _has_common_name_context(text: str, start: int) -> bool:
        prefix = text[max(0, start - 12):start]
        return bool(re.search(r"(?:^|\s)(?:김|이|박|최|정|강|조|윤|장|임|홍)[가-힣]{1,3}\s*$", prefix))

    @staticmethod
    def _has_name_on_previous_line(text: str, start: int) -> bool:
        prefix = text[:start]
        return bool(re.search(r"(?:^|\n)(?:김|이|박|최|정|강|조|윤|장|임|홍)[가-힣]{1,3}[ \t]*\r?\n[ \t]*$", prefix))

    @classmethod
    def _has_rrn_label_near(cls, text: str, start: int, end: int, window: int = 48) -> bool:
        snippet = text[max(0, start - window):min(len(text), end + 16)]
        return bool(cls._RRN_LABEL_RE.search(snippet))

    def _recover_structured_pii(self, ctx: DetectContext) -> None:
        text = ctx.text
        lowered = text.casefold()
        if re.search(r"\d", text) is None:
            if not any(label in lowered for label in ("주민", "외국인", "jumin", "resident", "birth", "serial")):
                return

        table_or_list_action = self._has_table_or_list_action(text)
        whole_candidate = len(text.strip()) <= 32
        rrn_hint = any(label in lowered for label in ("주민", "외국인", "생년월일", "뒷자리", "앞 6", "뒤 7", "jumin", "resident", "birth", "serial", "front", "back"))
        phone_hint = any(label in lowered for label in ("전화", "연락처", "휴대폰", "휴대전화", "phone", "mobile"))
        # Name-only recovery is for short prompt/cell values.  Running a broad
        # Korean-name regex over large numeric documents is costly and creates
        # little additional recall beyond the ordinary context detector.
        surname_hint = len(text) <= 512 and any(
            name in text for name in ("김", "이", "박", "최", "정", "강", "조", "윤", "장", "임", "홍")
        )
        common_name_context = surname_hint and bool(
            re.search(r"(?:^|\s)(?:김|이|박|최|정|강|조|윤|장|임|홍)[가-힣]{1,3}\s+", text)
        )
        previous_line_name = surname_hint and bool(
            re.search(r"(?:^|\n)(?:김|이|박|최|정|강|조|윤|장|임|홍)[가-힣]{1,3}[ \t]*\r?\n", text)
        )
        if not (whole_candidate or table_or_list_action or rrn_hint or phone_hint or common_name_context or previous_line_name):
            return

        if rrn_hint or whole_candidate or table_or_list_action:
            for matched in self._RRN_DIRECT_RE.finditer(text):
                validation_value = re.sub(r"%2[dD]", "-", matched.group(0))
                kind = self._rrn_type(validation_value)
                if kind:
                    self._add(ctx, kind[0], *matched.span(), "rrn_separator", isValid=True, checksum_status=kind[1])

        # Weak punctuation and arbitrary digit grouping are accepted only when
        # a resident-registration label is close to the candidate.  This keeps
        # generic numeric prose out while covering copy/paste and deliberate
        # separator changes.  Structure and checksum validation remain
        # mandatory after separators are removed.
        if rrn_hint:
            for matched in self._RRN_CONTEXT_SEPARATOR_RE.finditer(text):
                if not self._has_rrn_label_near(text, *matched.span()):
                    continue
                kind = self._rrn_type(matched.group(0))
                if kind:
                    if len(ctx.get(kind[0]) or []) >= ctx.max_results:
                        break
                    self._add(
                        ctx,
                        kind[0],
                        *matched.span(),
                        "rrn_context_separator",
                        isValid=True,
                        checksum_status=kind[1],
                    )
            for matched in self._RRN_CONTEXT_SPACED_RE.finditer(text):
                raw = matched.group(0)
                if not any(ch in raw for ch in (" ", "\t", "\u00a0", "\u3000")):
                    continue
                if not self._has_rrn_label_near(text, *matched.span()):
                    continue
                kind = self._rrn_type(raw)
                if kind:
                    if len(ctx.get(kind[0]) or []) >= ctx.max_results:
                        break
                    self._add(
                        ctx,
                        kind[0],
                        *matched.span(),
                        "rrn_context_spacing",
                        isValid=True,
                        checksum_status=kind[1],
                    )

        # Canonical standalone values are admitted only with checksum/Luhn or
        # an exact high-specificity layout.  Existing context-approved results
        # naturally de-duplicate in _finalize.
        if whole_candidate or table_or_list_action or previous_line_name:
            for matched in self._RRN_CANONICAL_RE.finditer(text):
                kind = self._rrn_type(matched.group(0))
                if kind and (
                    self._is_whole_value(text, *matched.span())
                    or table_or_list_action
                    or self._has_name_on_previous_line(text, matched.start())
                ):
                    self._add(ctx, kind[0], *matched.span(), "standalone_checksum", isValid=True, checksum_status=kind[1])
        if whole_candidate or table_or_list_action or common_name_context:
            for matched in self._CARD_CANONICAL_RE.finditer(text):
                if card_structure_valid(matched.group(0)) and (
                    self._is_whole_value(text, *matched.span())
                    or table_or_list_action
                    or self._has_common_name_context(text, matched.start())
                ):
                    self._add(ctx, "CN", *matched.span(), "standalone_luhn")
            for matched in self._DN_CANONICAL_RE.finditer(text):
                if (
                    self._is_whole_value(text, *matched.span())
                    or table_or_list_action
                    or self._has_common_name_context(text, matched.start())
                ):
                    self._add(ctx, "DN", *matched.span(), "standalone_exact_layout")

        if phone_hint and self._PHONE_LABEL_RE.search(text):
            for matched in self._PHONE_SPECIAL_RE.finditer(text):
                self._add(ctx, "MN", *matched.span(), "phone_parenthesis")

        if rrn_hint and self._RRN_LABEL_RE.search(text):
            for matched in self._HANGUL_DIGIT_RE.finditer(text):
                normalized = re.sub(r"\s+", "", matched.group(0)).translate(self._HANGUL_DIGITS)
                kind = self._rrn_type(normalized)
                if kind:
                    self._add(ctx, kind[0], *matched.span(), "hangul_digits", isValid=True, checksum_status=kind[1])

            for pattern in self._SPLIT_RRN_PATTERNS:
                for matched in pattern.finditer(text):
                    if matched.end() - matched.start() > self.max_split_span:
                        continue
                    groups = matched.groups()
                    normalized = groups[0] + (groups[1] + groups[2] if len(groups) == 3 else groups[1])
                    kind = self._rrn_type(normalized)
                    if kind:
                        self._add(ctx, kind[0], *matched.span(), "split_fields", isValid=True, checksum_status=kind[1])

    def _recover_fragmented_tokens(self, ctx: DetectContext) -> None:
        text = ctx.text
        if not any(
            trigger in text
            for trigger in (
                "AKIA", "ASIA", "akia", "asia", "A K I A", "A S I A", "a k i a", "a s i a",
                "ghp_", "gho_", "ghs_", "ghr_", "ghu_",
            )
        ):
            return
        for matched in self._AWS_FRAGMENT_RE.finditer(text):
            normalized = re.sub(r"\s+", "", matched.group(0)).upper()
            if re.fullmatch(r"(?:AKIA|ASIA)[A-Z0-9]{16}", normalized):
                self._add(ctx, "API_KEY", *matched.span(), "token_defrag")
        for matched in self._GITHUB_FRAGMENT_RE.finditer(text):
            normalized = matched.group(0)[:4] + matched.group(0)[4:].replace("-", "")
            if re.fullmatch(r"gh[oprsu]_[A-Za-z0-9]{36,255}", normalized):
                self._add(ctx, "API_KEY", *matched.span(), "token_defrag")

    def _recover_base64(self, ctx: DetectContext) -> None:
        text = ctx.text
        lowered = text.casefold()
        if not any(hint in lowered for hint in ("base64", "base 64", "디코딩", "디코드", "decode", "복호")):
            return
        count = 0
        for matched in self._BASE64_TOKEN_RE.finditer(text):
            if count >= self.max_transform_candidates:
                break
            count += 1
            token = matched.group(0)
            try:
                decoded_bytes = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
            except (binascii.Error, ValueError):
                continue
            # Detection-first PoC fallback for deliberately corrupted Base64:
            # require an explicit transform hint plus a strong AWS prefix and
            # at least twelve contiguous key characters in the decoded bytes.
            # We never treat arbitrary undecodable Base64 as a credential.
            if re.match(rb"(?:AKIA|ASIA)[A-Z0-9]{8,}", decoded_bytes):
                self._add(ctx, "API_KEY", *matched.span(), "base64_aws_prefix")
                continue
            try:
                decoded = decoded_bytes.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if re.fullmatch(r"(?:AKIA|ASIA)[A-Z0-9]{16}", decoded):
                self._add(ctx, "API_KEY", *matched.span(), "base64")
                continue
            kind = self._rrn_type(decoded)
            if kind:
                self._add(ctx, kind[0], *matched.span(), "base64", isValid=True, checksum_status=kind[1])

    def _recover_reverse(self, ctx: DetectContext) -> None:
        text = ctx.text
        lowered = text.casefold()
        if not any(hint in lowered for hint in ("뒤집", "역순", "reverse")):
            return
        for matched in self._REVERSE_TOKEN_RE.finditer(text):
            reversed_value = matched.group(0)[::-1].upper()
            if re.fullmatch(r"(?:AKIA|ASIA)[A-Z0-9]{16}", reversed_value):
                self._add(ctx, "API_KEY", *matched.span(), "reverse")
        for matched in re.finditer(r"(?<!\d)\d{7}-\d{6}(?!\d)", text):
            normalized = matched.group(0)[::-1]
            kind = self._rrn_type(normalized)
            if kind:
                self._add(ctx, kind[0], *matched.span(), "reverse", isValid=True, checksum_status=kind[1])

    def _recover_confusable_email(self, ctx: DetectContext) -> None:
        if "@" not in ctx.text or not re.search(r"[\u0400-\u04ff]", ctx.text):
            return
        for matched in self._CONFUSABLE_EMAIL_RE.finditer(ctx.text):
            skeleton = matched.group(0).translate(self._CYRILLIC_SKELETON)
            if skeleton != matched.group(0) and email_structure_valid(skeleton):
                self._add(ctx, "EML", *matched.span(), "confusable_email")

    def run(self, ctx: DetectContext) -> None:
        if not self.enabled:
            return
        self._recover_structured_pii(ctx)
        self._recover_fragmented_tokens(ctx)
        self._recover_base64(ctx)
        self._recover_reverse(ctx)
        self._recover_confusable_email(ctx)

class _LabeledAlternateSeparatorScanner:
    """Scan a short label-adjacent window for consistently separated digits.

    The ordinary MN/BN candidate regexes intentionally stay narrow.  Expanding
    their separator character classes makes punctuation-heavy documents create
    many candidates.  This scanner only becomes active when an explicit type
    label exists and only checks the text immediately following that label.
    """

    def __init__(self, config: Dict[str, Any] | None, detected_by: str):
        cfg = config if isinstance(config, dict) else {}
        self.enabled = bool(cfg.get("enabled", False))
        self.detected_by = detected_by
        self.max_window_chars = max(8, min(int(cfg.get("max_window_chars", 48)), 256))
        self.max_label_value_gap = max(0, min(int(cfg.get("max_label_value_gap", 8)), 32))
        self.separator_chars = str(cfg.get("separator_chars") or "")
        self._separator_set = set(self.separator_chars)
        self.labels = tuple(
            str(label).strip()
            for label in (cfg.get("labels") or [])
            if isinstance(label, str) and str(label).strip()
        )
        self._labels_casefold = tuple(label.casefold() for label in self.labels)
        self._label_re: Pattern | None = None
        self._value_regexes: List[Pattern] = []

        if not self.enabled or not self.labels or not self.separator_chars:
            self.enabled = False
            return

        labels_expr = "|".join(re.escape(label) for label in sorted(self.labels, key=len, reverse=True))
        self._label_re = re.compile(labels_expr, re.IGNORECASE)

        separator_expr = re.escape(self.separator_chars)
        for format_spec in cfg.get("formats") or []:
            quantifiers = self._parse_format(format_spec)
            if len(quantifiers) < 2:
                continue
            groups = [rf"\d{quantifier}" for quantifier in quantifiers]
            value_expr = groups[0] + rf"[ \t]*(?P<sep>[{separator_expr}])[ \t]*"
            value_expr += rf"[ \t]*(?P=sep)[ \t]*".join(groups[1:])
            self._value_regexes.append(
                re.compile(
                    rf"[ \t]*(?::|=)?[ \t]*(?P<value>{value_expr})(?!\d)"
                )
            )

        if not self._value_regexes:
            self.enabled = False

    @staticmethod
    def _parse_format(format_spec: Any) -> List[str]:
        if not isinstance(format_spec, list):
            return []
        quantifiers: List[str] = []
        for raw in format_spec:
            if isinstance(raw, int):
                minimum = maximum = raw
            else:
                matched = re.fullmatch(r"(\d{1,2})(?:-(\d{1,2}))?", str(raw).strip())
                if not matched:
                    return []
                minimum = int(matched.group(1))
                maximum = int(matched.group(2) or minimum)
            if minimum < 1 or maximum < minimum or maximum > 32:
                return []
            quantifiers.append(f"{{{minimum}}}" if minimum == maximum else f"{{{minimum},{maximum}}}")
        return quantifiers

    def scan(self, ctx: DetectContext) -> List[dict]:
        if not self.enabled or not ctx.text or self._label_re is None:
            return []

        # Casefolding is shared by MN and BN and avoids regex work when none of
        # the configured labels are present in a large input.
        folded = ctx.get_extra("labeled_alternate_separator:casefold")
        if folded is None:
            folded = ctx.text.casefold()
            ctx.set_extra("labeled_alternate_separator:casefold", folded)
        if not any(label in folded for label in self._labels_casefold):
            return []

        results: List[dict] = []
        text = ctx.text
        for label_match in self._label_re.finditer(text):
            label_end = label_match.end()
            window_end = min(len(text), label_end + self.max_window_chars)
            for newline in ("\r", "\n"):
                newline_at = text.find(newline, label_end, window_end)
                if newline_at >= 0:
                    window_end = min(window_end, newline_at)
            window = text[label_end:window_end]

            best: Tuple[int, int] | None = None
            for value_re in self._value_regexes:
                matched = value_re.match(window)
                if not matched:
                    continue
                value_start, value_end = matched.span("value")
                if value_start > self.max_label_value_gap:
                    continue

                # Do not accept a prefix of a longer or mixed-separator value.
                tail_pos = value_end
                while tail_pos < len(window) and window[tail_pos] in " \t":
                    tail_pos += 1
                if tail_pos < len(window) and window[tail_pos] in self._separator_set:
                    continue
                if best is None or value_end > best[1]:
                    best = (value_start, value_end)

            if best is None:
                continue
            start = label_end + best[0]
            end = label_end + best[1]
            results.append(
                {
                    "start": start,
                    "end": end,
                    "matchString": text[start:end],
                    "detected_by": self.detected_by,
                    "context_pass": True,
                    "context_accept_by": "explicit_numeric_label",
                }
            )
            if len(results) >= ctx.max_results:
                break

        return _finalize(results)


class MNPostFilter(Detector):
    def __init__(
        self,
        enabled: bool,
        boundary_digit_reject: bool,
        reject_overlap_with: List[str],
        intl_digits_len_min: int = 8,
        intl_digits_len_max: int = 15,
        reject_010_0_or_1xxx_4digit_middle: bool = True,
        alternate_separator: Dict[str, Any] | None = None,
    ):
        self.enabled = enabled
        self.boundary_digit_reject = boundary_digit_reject
        self.reject_overlap_with = reject_overlap_with
        self.intl_digits_len_min = intl_digits_len_min
        self.intl_digits_len_max = intl_digits_len_max
        self.reject_010_0_or_1xxx_4digit_middle = reject_010_0_or_1xxx_4digit_middle
        self.alternate_separator_scanner = _LabeledAlternateSeparatorScanner(
            alternate_separator,
            detected_by="labeled_alternate_separator:mn",
        )

    def run(self, ctx: DetectContext) -> None:
        if not self.enabled:
            return

        t0 = _timing_now()
        text = ctx.text
        mn_items = _finalize(self.alternate_separator_scanner.scan(ctx) + ctx.get("MN"))

        reject_spans: List[Tuple[int, int]] = []
        for key in self.reject_overlap_with:
            reject_spans.extend(_span_list(ctx.get(key)))

        filtered: List[dict] = []
        for it in mn_items:
            s, e = it["start"], it["end"]

            if self.boundary_digit_reject:
                if e < len(text) and text[e].isdigit():
                    continue
                if s > 0 and text[s - 1].isdigit():
                    continue

            ms = str(it.get("matchString", "")).strip()
            if not phone_structure_valid(ms):
                continue
            if self.reject_010_0_or_1xxx_4digit_middle:
                digits = _digits_only(_normalize_digit_text(ms))
                if len(digits) == 11 and digits[:4] in {"0100", "0101"}:
                    continue
            if ms.startswith("+"):
                dig = _digits_only(ms)
                if not (self.intl_digits_len_min <= len(dig) <= self.intl_digits_len_max):
                    continue

            if reject_spans and any(_overlaps(s, e, rs, re_) for rs, re_ in reject_spans):
                continue

            filtered.append(it)

        ctx.set("MN", _finalize(filtered))
        _log_timing("mn.postfilter", req_id=ctx.request_id, ms=f"{_timing_ms(t0):.1f}", input=len(mn_items), kept=len(filtered))


class BNPostFilter(Detector):
    def __init__(
        self,
        enabled: bool,
        digits_len_min: int,
        digits_len_max: int,
        reject_if_phone_like: bool,
        reject_if_rrn_like: bool,
        reject_if_brn_like: bool,
        boundary_digit_reject: bool,
        reject_overlap_with: List[str],
        phone_like_fullmatch_re: Pattern,
        alternate_separator: Dict[str, Any] | None = None,
    ):
        self.enabled = enabled
        self.digits_len_min = digits_len_min
        self.digits_len_max = digits_len_max
        self.reject_if_phone_like = reject_if_phone_like
        self.reject_if_rrn_like = reject_if_rrn_like
        self.reject_if_brn_like = reject_if_brn_like
        self.boundary_digit_reject = boundary_digit_reject
        self.reject_overlap_with = reject_overlap_with
        self.phone_like_fullmatch_re = phone_like_fullmatch_re
        alternate_cfg = alternate_separator if isinstance(alternate_separator, dict) else {}
        alternate_digits_len = alternate_cfg.get("digits_length") or {}
        self.alternate_digits_len_min = int(alternate_digits_len.get("min", digits_len_min))
        self.alternate_digits_len_max = int(alternate_digits_len.get("max", digits_len_max))
        self.alternate_separator_scanner = _LabeledAlternateSeparatorScanner(
            alternate_cfg,
            detected_by="labeled_alternate_separator:bn",
        )

    def run(self, ctx: DetectContext) -> None:
        if not self.enabled:
            return

        t0 = _timing_now()
        text = ctx.text
        bn_items = _finalize(self.alternate_separator_scanner.scan(ctx) + ctx.get("BN"))

        reject_spans: List[Tuple[int, int]] = []
        for key in self.reject_overlap_with:
            reject_spans.extend(_span_list(ctx.get(key)))

        filtered: List[dict] = []
        for it in bn_items:
            s, e = it["start"], it["end"]

            if self.boundary_digit_reject:
                if e < len(text) and text[e].isdigit():
                    continue
                if s > 0 and text[s - 1].isdigit():
                    continue

            dig = _digits_only(it["matchString"])
            is_alternate = it.get("detected_by") in {
                "labeled_alternate_separator:bn",
                "numeric_alternate_separator:bn",
            }
            digits_len_min = self.alternate_digits_len_min if is_alternate else self.digits_len_min
            digits_len_max = self.alternate_digits_len_max if is_alternate else self.digits_len_max
            if not (digits_len_min <= len(dig) <= digits_len_max):
                continue

            if self.reject_if_phone_like:
                if self.phone_like_fullmatch_re.fullmatch(it["matchString"].strip()):
                    continue

            # RRN-like rejection is intended for compact or hyphenated resident
            # numbers. Space-separated account formats can be structurally RRN-like
            # after stripping non-digits, so do not reject those here.
            if self.reject_if_rrn_like and " " not in str(it["matchString"]) and rrn_candidate_shape(it["matchString"]):
                continue

            if self.reject_if_brn_like and brn_candidate_shape(it["matchString"]):
                if "-" in str(it["matchString"]) or brn_context_hint(text, s, e):
                    continue

            if reject_spans and any(_overlaps(s, e, rs, re_) for rs, re_ in reject_spans):
                continue

            filtered.append(it)

        ctx.set("BN", _finalize(_select_non_overlapping(_dedup_sorted(filtered))))
        _log_timing("bn.postfilter", req_id=ctx.request_id, ms=f"{_timing_ms(t0):.1f}", input=len(bn_items), kept=len(filtered))


# ============================================================
# Contextual post-filter (sentence-window based)
# ============================================================


