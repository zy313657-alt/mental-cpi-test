const corsHeaders = {
  "Access-Control-Allow-Origin": Deno.env.get("CPI_SITE_ORIGIN") ?? "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Vary": "Origin",
};

const url = Deno.env.get("SUPABASE_URL")!;
const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const anonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
const adminEmail = (Deno.env.get("CPI_ADMIN_EMAIL") ?? "").toLowerCase();

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}

async function sha256(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value.trim().toUpperCase()));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function rest(path: string, init: RequestInit = {}) {
  const response = await fetch(`${url}/rest/v1/${path}`, {
    ...init,
    headers: {
      apikey: serviceKey,
      Authorization: `Bearer ${serviceKey}`,
      "Content-Type": "application/json",
      ...(init.headers ?? {}),
    },
  });
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;
  if (!response.ok) throw new Error(data?.message ?? `Supabase request failed (${response.status})`);
  return data;
}

async function requireAdmin(request: Request) {
  if (!adminEmail) throw new Error("管理员邮箱尚未配置");
  const token = request.headers.get("Authorization")?.replace(/^Bearer\s+/i, "");
  if (!token) throw new Error("请先登录管理后台");
  const response = await fetch(`${url}/auth/v1/user`, {
    headers: { apikey: anonKey, Authorization: `Bearer ${token}` },
  });
  if (!response.ok) throw new Error("管理员登录已失效，请重新登录");
  const user = await response.json();
  if ((user.email ?? "").toLowerCase() !== adminEmail) throw new Error("此账号没有后台管理权限");
}

Deno.serve(async (request) => {
  if (request.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const pathname = new URL(request.url).pathname.split("/").filter(Boolean).at(-1) ?? "";
  try {
    const input = request.method === "POST" ? await request.json() : {};

    if (pathname === "validate" && request.method === "POST") {
      const code = String(input.code ?? "").trim();
      if (!code || code.length > 128) return json({ error: "请输入有效密码" }, 400);
      const response = await fetch(`${url}/rest/v1/rpc/cpi_validate_code`, {
        method: "POST",
        headers: { apikey: serviceKey, Authorization: `Bearer ${serviceKey}`, "Content-Type": "application/json" },
        body: JSON.stringify({ p_code_hash: await sha256(code) }),
      });
      const data = await response.json();
      if (!response.ok) return json({ error: data.message ?? "密码验证失败" }, 403);
      return json({ ok: true, remaining: data?.[0]?.remaining ?? 0 });
    }

    if (pathname === "result" && request.method === "POST") {
      const code = String(input.code ?? "").trim();
      const score = Number(input.score), cpi = Number(input.cpi);
      if (!code || !Number.isInteger(score) || score < 12 || score > 48 || !Number.isInteger(cpi) || cpi < 0 || cpi > 100) {
        return json({ error: "结果数据无效" }, 400);
      }
      await rest("cpi_results", { method: "POST", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ code_hash: await sha256(code), score, cpi }) });
      return json({ ok: true });
    }

    if (pathname === "admin-login" && request.method === "POST") {
      const response = await fetch(`${url}/auth/v1/token?grant_type=password`, {
        method: "POST", headers: { apikey: anonKey, "Content-Type": "application/json" }, body: JSON.stringify(input),
      });
      const data = await response.json();
      if (!response.ok) return json({ error: data.msg ?? data.message ?? "登录失败" }, 401);
      if ((data.user?.email ?? "").toLowerCase() !== adminEmail) return json({ error: "此账号没有后台管理权限" }, 403);
      return json({ access_token: data.access_token, refresh_token: data.refresh_token, expires_in: data.expires_in, user: { email: data.user.email } });
    }

    if (pathname.startsWith("admin-") && pathname !== "admin-login") {
      await requireAdmin(request);
      if (pathname === "admin-codes" && request.method === "GET") {
        const [codes, results] = await Promise.all([
          rest("cpi_test_codes?select=id,code_display,label,max_uses,used_count,active,created_at&order=created_at.desc"),
          rest("cpi_results?select=id"),
        ]);
        return json({ codes, stats: { codes: codes.length, uses: codes.reduce((sum: number, row: any) => sum + row.used_count, 0), results: results.length } });
      }
      if (pathname === "admin-codes" && request.method === "POST") {
        const maxUses = Number(input.max_uses ?? 3), quantity = Number(input.quantity ?? 1);
        if (!Number.isInteger(maxUses) || maxUses < 1 || maxUses > 1000 || !Number.isInteger(quantity) || quantity < 1 || quantity > 100) return json({ error: "次数需为 1–1000，每次最多生成 100 个密码" }, 400);
        const generated = Array.from({ length: quantity }, () => `CPI-${crypto.randomUUID().replaceAll("-", "").slice(0, 6).toUpperCase()}-${crypto.randomUUID().replaceAll("-", "").slice(0, 4).toUpperCase()}`);
        await rest("cpi_test_codes", { method: "POST", headers: { Prefer: "return=minimal" }, body: JSON.stringify(await Promise.all(generated.map(async (code) => ({ code_hash: await sha256(code), code_display: code, label: String(input.label ?? "").slice(0, 80), max_uses: maxUses })))) });
        return json({ codes: generated }, 201);
      }

      if (pathname === "admin-password" && request.method === "POST") {
        const token = request.headers.get("Authorization")?.replace(/^Bearer\s+/i, "");
        const response = await fetch(`${url}/auth/v1/user`, { method: "PUT", headers: { apikey: anonKey, Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify({ password: input.password }) });
        const data = await response.json();
        if (!response.ok) return json({ error: data.message ?? "口令更新失败" }, 400);
        return json({ ok: true });
      }

      const id = pathname.match(/^admin-code-(\d+)-(reset|toggle|delete)$/);
      if (id && request.method === "POST") {
        const [, codeId, action] = id;
        if (action === "reset") await rest(`cpi_test_codes?id=eq.${codeId}`, { method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ used_count: 0 }) });
        else if (action === "toggle") {
          const rows = await rest(`cpi_test_codes?id=eq.${codeId}&select=active`);
          if (!rows.length) return json({ error: "密码不存在" }, 404);
          await rest(`cpi_test_codes?id=eq.${codeId}`, { method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ active: !rows[0].active }) });
        } else await rest(`cpi_test_codes?id=eq.${codeId}`, { method: "DELETE", headers: { Prefer: "return=minimal" } });
        return json({ ok: true });
      }
    }
    return json({ error: "未找到" }, 404);
  } catch (error) {
    const message = error instanceof Error ? error.message : "服务暂时不可用";
    return json({ error: message }, message.includes("登录") || message.includes("权限") ? 401 : 500);
  }
});
