//! [#doorwest-perf3] paginate pass 범위 측정 메모.
//!
//! 한 번의 paginate pass 안에서 measure(HeightMeasurer)와 typeset(TypesetEngine)이
//! 같은 `composed` 슬라이스의 같은 줄을 `stored_rows_are_stale` →
//! `estimate_composed_line_width` 로 각각 재측정한다(생성자 시간의 큰 몫). 이 모듈은
//! 그 순수 함수 결과를 pass 동안만 메모한다:
//!
//! - 줄 폭: 키 = (styles 객체 주소, run 내용 지문). `estimate_composed_line_width` 는
//!   (run 내용, styles) 만의 순수 함수라 같은 지문·같은 styles면 결과가 같다. styles는
//!   pass 중 불변이라 주소로 대조한다.
//! - 부실 판정: 키 = (para 주소, composed 주소, 폭 비트, squeeze, 문단·줄 수 판별자).
//!   pass 중 para_src·composed 배열은 읽기 전용(측정·조판은 `&` 참조만 받고 사본을
//!   재구성한다)이라 pass 내에서는 같은 주소 = 같은 내용이다.
//!
//! 안전 계약:
//! - pass 밖(편집·진단·export·렌더)에서는 아예 캐시를 보지 않는다 — `PassScope` 이
//!   arm 하고 drop/`end_pass` 에서 disarm·전면 clear 하므로, pass 사이의 주소 재사용이
//!   값에 스며들 수 없다.
//! - 지문은 폭 계산이 읽는 run 필드 전부(text·display_text 바이트 포함)를 흡수한다.
//!   char_overlap은 내부 구성이 아니라 존재·스칼라 필드만 폭 경로가 읽으므로 그만큼만
//!   흡수한다. 지문이 같아도 styles 주소가 다르면(다른 pass) 히트하지 않는다.
//! - 저장 오류(Err) 결과는 캐시하지 않는다.
//!
//! wasm32 단일 스레드, 네이티브 paginate도 단일 스레드 — thread_local 로 충분하다.

use std::cell::RefCell;
use std::collections::HashMap;

const MAX_LINE_ENTRIES: usize = 400_000;
const MAX_VERDICT_ENTRIES: usize = 400_000;

thread_local! {
    static PASS_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    static LINE_WIDTH: RefCell<HashMap<(usize, u64), f64>> = RefCell::new(HashMap::new());
    static VERDICT: RefCell<HashMap<VerdictKey, bool>> = RefCell::new(HashMap::new());
}

/// 측정·부실 판정 결과 캐시의 키.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct VerdictKey {
    para_addr: usize,
    composed_addr: usize,
    width_bits: u64,
    squeeze: bool,
    /// 판별자: line_segs 수·본문 바이트 수·구성 줄 수. 같은 주소라 다른 내용일 가능성을
    /// (빈 저장 줄 지역 사본 등) 필드 차이로 가린다.
    disc: u64,
}

/// paginate pass 하나의 캐시 생존 구간. `begin()` 부터 drop 까지 arm 상태고, drop 시
/// depth 를 줄여 0이 되면 disarm·clear 한다(중첩 paginate pass 지원).
pub(crate) struct PassScope {
    _private: (),
}

impl PassScope {
    pub(crate) fn begin() -> Self {
        PASS_DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
        Self { _private: () }
    }

    pub(crate) fn end_pass() {
        PASS_DEPTH.with(|depth| {
            let remaining = depth.get().saturating_sub(1);
            depth.set(remaining);
            if remaining == 0 {
                LINE_WIDTH.with(|cache| cache.borrow_mut().clear());
                VERDICT.with(|cache| cache.borrow_mut().clear());
            }
        });
    }
}

impl Drop for PassScope {
    fn drop(&mut self) {
        Self::end_pass();
    }
}

pub(crate) fn pass_armed() -> bool {
    PASS_DEPTH.with(|depth| depth.get() > 0)
}

/// u64 혼합기 — measure/typeset 재측정 제거가 목적이라 암호학적 성질은 불필요하고,
/// 내용 차이가 지문에 반영되는 것만 충분하다. 글자 폭 결정 메모
/// ([`crate::renderer::layout::text_measurement`])도 표준 SipHash 대신 이 혼합기를 쓴다 —
/// 글자마다의 해시가 문지방이 되기 때문이다(히트는 내용 검증이 뒤따른다).
pub(crate) fn mix_u64(hash: &mut u64, word: u64) {
    *hash ^= word;
    *hash = hash.wrapping_mul(0xff51_afd7_ed55_8ccd);
    *hash ^= *hash >> 29;
}

pub(crate) fn mix_bytes(hash: &mut u64, bytes: &[u8]) {
    let mut chunks = bytes.chunks_exact(8);
    for chunk in &mut chunks {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(chunk);
        mix_u64(hash, u64::from_le_bytes(buf));
    }
    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        let mut buf = [0u8; 8];
        buf[..remainder.len()].copy_from_slice(remainder);
        mix_u64(hash, u64::from_le_bytes(buf));
    }
}

fn mix_usize(hash: &mut u64, value: usize) {
    mix_u64(hash, value as u64);
}

/// 폭 계산이 읽는 run 필드 전부를 흡수한 줄 지문. 필드를 추가하면 폭 결과가 달라질 수
/// 있으니 여기도 함께 흡수할 것 — 이 주석이 컴파일러의 필드 점검을 대신한다.
fn run_fingerprint(hash: &mut u64, run: &super::ComposedTextRun) {
    mix_u64(hash, u64::from(run.literal_soft_hyphen));
    mix_u64(hash, u64::from(run.literal_figure_space));
    mix_bytes(hash, run.text.as_bytes());
    mix_u64(hash, u64::from(run.char_style_id));
    mix_usize(hash, run.lang_index);
    mix_u64(hash, run.neutral_space_origin.map_or(u64::MAX, |v| v as u64));
    match &run.char_overlap {
        None => mix_u64(hash, 0x9E37_79B9_7F4A_7C15),
        Some(overlap) => {
            // 폭 경로가 char_overlap에서 읽는 것은 존재와 공개 스칼라뿐이다
            // (owns_mapped_symbol_font·apply_font 의 존재 검사, 내부 구성은
            // 렌더 전용). 구성 내용까지 흡수하지 않는 이유가 이것이다.
            mix_u64(hash, u64::from(overlap.border_type));
            mix_u64(hash, i64::from(overlap.inner_char_size) as u64);
            mix_u64(hash, u64::from(overlap.empty_ink));
            mix_u64(hash, overlap.composition.is_some() as u64);
        }
    }
    mix_u64(hash, run.footnote_marker.map_or(u64::MAX, u64::from));
    match &run.display_text {
        None => mix_u64(hash, 0xFEDC_BA98_7654_3210),
        Some(display) => mix_bytes(hash, display.as_bytes()),
    }
    mix_u64(hash, u64::from(run.supplemental_metrics_blocked));
    mix_u64(hash, u64::from(run.inserted_control_text));
    mix_u64(hash, run.space_metric as u64);
    mix_u64(hash, u64::from(run.regenerated_font_metrics));
}

fn line_fingerprint(line: &super::ComposedLine) -> u64 {
    let mut hash = 0xC0FF_EE12_3456_789Au64;
    mix_usize(&mut hash, line.runs.len());
    for run in &line.runs {
        run_fingerprint(&mut hash, run);
    }
    hash
}

/// `estimate_composed_line_width` 의 pass 범위 메모. arm 상태가 아니면 계산을 그대로
/// 실행하고, 저장 오류는 캐시하지 않는다.
pub(crate) fn cached_line_width<E>(
    line: &super::ComposedLine,
    styles: &crate::renderer::style_resolver::ResolvedStyleSet,
    compute: impl FnOnce() -> Result<f64, E>,
) -> Result<f64, E> {
    if !pass_armed() {
        return compute();
    }
    let styles_addr = std::ptr::from_ref(styles) as usize;
    let key = (styles_addr, line_fingerprint(line));
    let hit = LINE_WIDTH.with(|cache| cache.borrow().get(&key).copied());
    if let Some(width) = hit {
        return Ok(width);
    }
    let width = compute()?;
    LINE_WIDTH.with(|cache| {
        let mut cache = cache.borrow_mut();
        if cache.len() >= MAX_LINE_ENTRIES {
            cache.clear();
        }
        cache.insert(key, width);
    });
    Ok(width)
}

/// `stored_rows_are_stale` 의 pass 범위 메모. arm 상태가 아니면 계산을 그대로 실행하고,
/// 저장 오류는 캐시하지 않는다.
pub(crate) fn cached_stale_verdict<E>(
    composed: &super::ComposedParagraph,
    para: &crate::model::paragraph::Paragraph,
    inner_width_px: f64,
    line_wrap_squeeze: bool,
    compute: impl FnOnce() -> Result<bool, E>,
) -> Result<bool, E> {
    if !pass_armed() {
        return compute();
    }
    let key = VerdictKey {
        para_addr: std::ptr::from_ref(para) as usize,
        composed_addr: std::ptr::from_ref(composed) as usize,
        width_bits: inner_width_px.to_bits(),
        squeeze: line_wrap_squeeze,
        disc: ((para.line_segs.len() as u64) << 32)
            ^ ((para.text.len() as u64) << 16)
            ^ (composed.lines.len() as u64),
    };
    let hit = VERDICT.with(|cache| cache.borrow().get(&key).copied());
    if let Some(verdict) = hit {
        return Ok(verdict);
    }
    let verdict = compute()?;
    VERDICT.with(|cache| {
        let mut cache = cache.borrow_mut();
        if cache.len() >= MAX_VERDICT_ENTRIES {
            cache.clear();
        }
        cache.insert(key, verdict);
    });
    Ok(verdict)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_scope_arms_and_clears_on_drop() {
        assert!(!pass_armed());
        let scope = PassScope::begin();
        assert!(pass_armed());
        drop(scope);
        assert!(!pass_armed());
    }

    #[test]
    fn nested_pass_scope_stays_armed_until_outer_drop() {
        let outer = PassScope::begin();
        let inner = PassScope::begin();
        assert!(pass_armed());
        drop(inner);
        assert!(pass_armed(), "중첩 pass 는 바깥이 끝나야 닫힌다");
        drop(outer);
        assert!(!pass_armed());
    }

    #[test]
    fn line_fingerprint_distinguishes_text_and_style_id() {
        use crate::renderer::composer::{ComposedLine, ComposedTextRun};
        let mut a = ComposedTextRun::default();
        a.text = "가나다".to_owned();
        let line_a = ComposedLine {
            runs: vec![a],
            line_height: 0,
            baseline_distance: 0,
            segment_width: 0,
            column_start: 0,
            line_spacing: 0,
            has_line_break: false,
            char_start: 0,
        };
        let mut line_b = line_a.clone();
        assert_eq!(line_fingerprint(&line_a), line_fingerprint(&line_b));
        line_b.runs[0].text.push('라');
        assert_ne!(line_fingerprint(&line_a), line_fingerprint(&line_b));
        line_b = line_a.clone();
        line_b.runs[0].char_style_id = 7;
        assert_ne!(line_fingerprint(&line_a), line_fingerprint(&line_b));
    }
}
