/**
 * 폐기물처리시설 검사·진단 플랫폼 — 법령 API 중계 서버 (Cloudflare Worker)
 *
 * 하는 일
 *   사이트(ultraki4-a11y.github.io)가 보낸 법령 조회 요청을 받아
 *   인증키(OC)를 서버에서 붙여 국가법령정보센터에 대신 묻고, 결과만 돌려줍니다.
 *   → 인증키가 웹페이지 코드에 드러나지 않습니다.
 *
 * 설정 (Cloudflare 대시보드 → 이 Worker → Settings → Variables and Secrets)
 *   LAW_OC          (Secret)  국가법령정보 OPEN API 인증키
 *   ALLOWED_ORIGINS (Text, 선택) 허용할 사이트 주소. 쉼표로 여러 개. 기본값은 아래 DEFAULT_ORIGINS
 *   LAW_REFERER     (Text, 선택) 법제처에 등록한 도메인 주소. 기본값 https://ultraki4-a11y.github.io/
 *
 * 요청 형식
 *   GET  https://<worker 주소>/law/lawSearch.do?target=law&query=폐기물관리법
 *   GET  https://<worker 주소>/law/lawService.do?target=law&MST=123456
 *   GET  https://<worker 주소>/health   → 상태 확인
 */
const DEFAULT_ORIGINS = ["https://ultraki4-a11y.github.io"];
const LAW_BASE = "https://www.law.go.kr/DRF/";
const ALLOWED_SVC = new Set(["lawSearch.do", "lawService.do"]);
const ALLOWED_TARGET = new Set(["law", "admrul"]);
const ALLOWED_PARAMS = new Set(["target", "query", "MST", "ID", "display", "page", "search", "sort", "org", "knd"]);
const CACHE_SECONDS = 6 * 3600;          // 같은 요청은 6시간 동안 저장본으로 응답 (법제처 부담·속도 개선)
const RATE_LIMIT = 120;                   // IP당 1분에 최대 요청 수 (같은 서버 인스턴스 기준)

const hits = new Map();
function rateLimited(ip) {
  const now = Date.now(), win = 60000;
  const h = hits.get(ip) || { t: now, n: 0 };
  if (now - h.t > win) { h.t = now; h.n = 0; }
  h.n++; hits.set(ip, h);
  if (hits.size > 5000) hits.clear();
  return h.n > RATE_LIMIT;
}
function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}
function json(body, status, origin) {
  return new Response(JSON.stringify(body), {
    status, headers: { "Content-Type": "application/json; charset=utf-8", ...(origin ? corsHeaders(origin) : {}) },
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const allowed = (env.ALLOWED_ORIGINS ? env.ALLOWED_ORIGINS.split(",").map(s => s.trim()) : DEFAULT_ORIGINS);
    const origin = request.headers.get("Origin") || "";
    const okOrigin = allowed.includes(origin) ? origin : "";

    if (request.method === "OPTIONS") {
      return okOrigin ? new Response(null, { status: 204, headers: corsHeaders(okOrigin) }) : new Response(null, { status: 403 });
    }
    if (url.pathname === "/health") {
      return json({ ok: true, key: !!env.LAW_OC, origins: allowed }, 200, okOrigin);
    }
    if (request.method !== "GET") return json({ error: "GET만 허용됩니다" }, 405, okOrigin);

    // 허용된 사이트에서 온 요청만 처리 (다른 사이트가 이 서버를 가져다 쓰지 못하게)
    if (!okOrigin) return json({ error: "허용되지 않은 출처입니다" }, 403, "");
    if (!env.LAW_OC) return json({ error: "서버에 LAW_OC가 설정되지 않았습니다" }, 500, okOrigin);

    const m = url.pathname.match(/^\/law\/([A-Za-z]+\.do)$/);
    if (!m || !ALLOWED_SVC.has(m[1])) return json({ error: "허용되지 않은 요청입니다" }, 400, okOrigin);
    const target = url.searchParams.get("target");
    if (!ALLOWED_TARGET.has(target)) return json({ error: "허용되지 않은 대상입니다" }, 400, okOrigin);

    const ip = request.headers.get("CF-Connecting-IP") || "?";
    if (rateLimited(ip)) return json({ error: "요청이 너무 많습니다. 잠시 후 다시 시도하십시오" }, 429, okOrigin);

    // 허용된 항목만 골라 법제처 요청 주소를 만듦 (인증키는 여기서만 붙음)
    const q = new URLSearchParams();
    q.set("OC", env.LAW_OC); q.set("type", "JSON");
    for (const [k, v] of url.searchParams) if (ALLOWED_PARAMS.has(k) && v.length < 300) q.set(k, v);
    const upstream = LAW_BASE + m[1] + "?" + q.toString();

    // 저장본(캐시) 먼저 확인 — 캐시 열쇠에는 인증키가 들어가지 않게 함
    const cacheKey = new Request("https://cache.local/" + m[1] + "?" + [...q].filter(([k]) => k !== "OC").map(([k, v]) => k + "=" + encodeURIComponent(v)).sort().join("&"));
    const cache = caches.default;
    const cached = await cache.match(cacheKey);
    if (cached) {
      const r = new Response(cached.body, cached);
      Object.entries(corsHeaders(okOrigin)).forEach(([k, v]) => r.headers.set(k, v));
      r.headers.set("X-Cache", "HIT");
      return r;
    }

    let res;
    try {
      res = await fetch(upstream, {
        headers: {
          "Referer": env.LAW_REFERER || "https://ultraki4-a11y.github.io/",
          "User-Agent": "Mozilla/5.0 (waste-inspection proxy)",
          "Accept": "application/json",
        },
        cf: { cacheTtl: 0 },
      });
    } catch (e) {
      return json({ error: "국가법령정보센터에 연결하지 못했습니다" }, 502, okOrigin);
    }
    const text = await res.text();
    if (!res.ok) return json({ error: "국가법령정보센터 응답 오류 (" + res.status + ")" }, 502, okOrigin);

    const out = new Response(text, {
      status: 200,
      headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "public, max-age=" + CACHE_SECONDS, ...corsHeaders(okOrigin) },
    });
    // 정상 JSON일 때만 저장 (오류 메시지는 저장하지 않음)
    if (text.trim().startsWith("{") && !/"result"\s*:\s*"실패"|미신청|인증/.test(text.slice(0, 300))) {
      ctx.waitUntil(cache.put(cacheKey, out.clone()));
    }
    out.headers.set("X-Cache", "MISS");
    return out;
  },
};
