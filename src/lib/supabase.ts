// Supabase client — eagerly initialized (static import).
// The package is a hard dependency in package.json, so no lazy-import dance needed.
// Lazy init caused a race: onAuthChange() got a no-op subscription at mount
// because the client wasn't ready yet, so the App never heard about logins.

import { createClient } from "@supabase/supabase-js";

export const supabase = createClient(
  "https://gnzcvhyxiatcjofywkdq.supabase.co",
  import.meta.env.VITE_SUPABASE_ANON_KEY ||
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImduemN2aHl4aWF0Y2pvZnl3a2RxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjE4Nzc2NDksImV4cCI6MjA3NzQ1MzY0OX0.8Pe2AXbKlhvO_j5ldEgNm81QuGRZHYTRrVWauQBZ3ls",
  {
    auth: {
      storage: typeof window !== "undefined" ? window.localStorage : undefined,
      autoRefreshToken: true,
      persistSession: true,
      detectSessionInUrl: false,
    },
  }
);

console.log("[Supabase] client eagerly initialized:", !!supabase);

// ── Terminal debug monitor ───────────────────────────────────
// Forwards a message to the Rust terminal (visible in `npm run tauri dev`)
// AND to hebed-proxy/console.log (visible in the app's "Show Logs").
// Use this to trace every payload sent to Supabase.
async function supabaseLog(message: string) {
  try {
    const { invoke } = await import("@tauri-apps/api/core");
    await invoke("supabase_log", { message });
  } catch {
    // Non-Tauri environment (plain browser): just console it
    console.log("[Supabase][term]", message);
  }
}

// ── PKCE Auth ─────────────────────────────────────────────────

async function _findFreePort(): Promise<number> {
  // Just probe incrementally — the Rust start_auth_server will tell us if port is taken.
  // We pick a base port and let the real start_auth_server try it.
  return 19950 + Math.floor(Math.random() * 40); // 19950-19989
}

export async function startPkceAuth(path: "/auth/signin" | "/auth/signup") {
  try {
    const port = await _findFreePort();
    console.log("[PKCE] using port:", port);

    const { invoke } = await import("@tauri-apps/api/core");
    await invoke("start_auth_server", { port });
    console.log("[PKCE] server started on port", port);

    const authUrl = `https://hebedai.com${path}?source=proxy&port=${port}`;
    console.log("[PKCE] opening browser:", authUrl);
    // Use Tauri's shell opener — window.open is blocked in WebView
    try {
      const { openUrl } = await import("@tauri-apps/plugin-opener");
      await openUrl(authUrl);
    } catch {
      window.open(authUrl, "_blank"); // fallback for browser dev mode
    }

    // Poll for session
    const sessionJson: string = await new Promise((resolve, reject) => {
      let polls = 0;
      const poll = setInterval(async () => {
        try {
          polls++;
          const result = await invoke<string | null>("get_auth_session");
          if (result) { clearInterval(poll); resolve(result); }
          if (polls % 10 === 0) console.log("[PKCE] polling #" + polls + "...");
        } catch { /* keep polling */ }
      }, 500);
      setTimeout(() => { clearInterval(poll); reject(new Error("Auth timeout")); }, 120000);
    });

    if (sessionJson) {
      console.log("[PKCE] session JSON received from Rust, len:", sessionJson.length);
      const { access_token, refresh_token } = JSON.parse(sessionJson);
      console.log("[PKCE] access_token len:", (access_token || "").length, "| refresh_token len:", (refresh_token || "").length);
      const { data, error } = await supabase.auth.setSession({ access_token, refresh_token });
      if (error) console.error("[PKCE] setSession error:", JSON.stringify(error));
      console.log("[PKCE] setSession done. session:", data.session ? data.session.user.email : "NO SESSION", "| event will fire via onAuthChange");
      return data.session;
    }
    console.log("[PKCE] no session JSON — poll timed out or cancelled");
    return null;
  } catch (e) {
    console.error("[PKCE] error:", e);
    return null;
  } finally {
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("stop_auth_server");
    } catch { /* */ }
  }
}

// ── Auth helpers ──────────────────────────────────────────────

export async function signOut() {
  return supabase.auth.signOut();
}

export async function getSession() {
  const { data } = await supabase.auth.getSession();
  return data.session;
}

export function onAuthChange(callback: (session: any) => void) {
  return supabase.auth.onAuthStateChange((_event: any, session: any) => callback(session));
}

export async function pushProxyEvent(event: {
  user_id: string; flow_id: string; event_type: "text_redact" | "file_scan";
  endpoint?: string; content_type?: string;
  entities?: { type: string; score: number }[];
  pii_count?: number; pii_preview?: string[];
  file_name?: string; file_size?: number;
  text_len?: number; extract_ms?: number; redacted?: boolean;
}) {
  const { error } = await supabase.from("proxy_logs").insert({
    ...event, entities: event.entities || [],
    pii_count: event.pii_count || 0, pii_preview: event.pii_preview || [],
  });
  if (error) console.error("[Supabase] pushProxyEvent:", error);
  return !error;
}

// ── files.log sync → proxy_logs ─────────────────────────────
// Reads the addon's files.log (via the Rust get_pii_events command, which
// already parses it into JSON events) and POSTs each file_scan row to the
// proxy_logs table.
//
// IMPORTANT (RLS): proxy_logs INSERT policy requires auth.uid() = user_id,
// so user_id MUST be the session user's id (auth.users.id). organization_id
// is retrieved from public.users (whose id == auth.users.id on this project)
// and may be null if the user row is missing.
export async function pushFileLogsToProxy(opts?: { limit?: number }): Promise<{
  ok: boolean;
  pushed: number;
  skipped: number;
  error?: string;
}> {
  try {
    const session = await getSession();
    if (!session?.user) return { ok: false, pushed: 0, skipped: 0, error: "Not signed in" };
    const user_id = session.user.id; // auth.uid() — RLS requires this exact value

    // Retrieve the user's organization_id (public.users.id == auth.users.id)
    const { data: userRow } = await supabase
      .from("users")
      .select("organization_id")
      .eq("id", user_id)
      .maybeSingle();
    const organization_id = userRow?.organization_id ?? null;
    console.log("[Supabase] pushFileLogs user_id:", user_id, "| organization_id:", organization_id);
    await supabaseLog(`[files.log] user_id=${user_id} organization_id=${organization_id}`);

    // Read files.log through the existing Rust command (already parsed JSON)
    const { invoke } = await import("@tauri-apps/api/core");
    const events = await invoke<any[]>("get_pii_events", { limit: opts?.limit ?? 200 });
    const fileScans = (events || []).filter((e) => e.event === "file_scan");
    await supabaseLog(`[files.log] read ${(events || []).length} pii_events, ${fileScans.length} file_scan rows`);
    if (fileScans.length === 0) return { ok: true, pushed: 0, skipped: 0 };

    // Dedupe: skip rows already present for this user (same flow_id + file + ts)
    const { data: existing } = await supabase
      .from("proxy_logs")
      .select("flow_id, file_name, ts")
      .eq("user_id", user_id)
      .in("flow_id", fileScans.map((e) => e.flow_id).filter(Boolean));
    const seen = new Set(
      (existing || []).map((r) => `${r.flow_id}|${r.file_name}|${r.ts}`)
    );
    const fresh = fileScans.filter(
      (e) => !seen.has(`${e.flow_id}|${e.filename}|${e.ts}`)
    );
    const skipped = fileScans.length - fresh.length;
    if (fresh.length === 0) return { ok: true, pushed: 0, skipped };

    const rows = fresh.map((ev) => ({
      user_id,
      organization_id,
      flow_id: ev.flow_id,
      event_type: "file_scan" as const,
      endpoint: ev.url,
      content_type: ev.content_type,
      entities: ev.entities ?? [],
      pii_count: ev.pii_count ?? 0,
      pii_preview: ev.pii_preview ?? [],
      file_name: ev.filename,
      file_size: ev.size,
      text_len: ev.text_len,
      extract_ms: ev.extract_ms,
      redacted: ev.redacted ?? false,
      ts: ev.ts,
    }));

    // Terminal debug: show exactly what is about to be sent
    await supabaseLog(`[files.log] SENDING ${rows.length} rows (skipped ${skipped})`);
    for (const r of rows.slice(0, 5)) {
      await supabaseLog(
        `  file_scan flow=${r.flow_id} name=${r.file_name ?? ""} pii=${r.pii_count} ` +
        `len=${r.text_len ?? 0} ct=${r.content_type ?? ""} ts=${r.ts ?? ""}`
      );
    }
    if (rows.length > 5) await supabaseLog(`  ... and ${rows.length - 5} more`);

    const { error } = await supabase.from("proxy_logs").insert(rows);
    if (error) {
      console.error("[Supabase] pushFileLogs insert error:", error);
      await supabaseLog(`[files.log] INSERT ERROR: ${error.message}`);
      return { ok: false, pushed: 0, skipped, error: error.message };
    }
    console.log(`[Supabase] pushFileLogs pushed ${rows.length} rows (skipped ${skipped})`);
    await supabaseLog(`[files.log] INSERT OK: ${rows.length} rows pushed (skipped ${skipped})`);
    return { ok: true, pushed: rows.length, skipped };
  } catch (e) {
    console.error("[Supabase] pushFileLogs error:", e);
    return { ok: false, pushed: 0, skipped: 0, error: String(e) };
  }
}

// ── prompts.log sync → proxy_logs ───────────────────────────
// Reads the addon's prompts.log (intercepted + transformed prompt content,
// via the Rust get_prompt_events command) and POSTs each prompt_redact row
// to the proxy_logs table with event_type "text_redact".
//
// Same RLS care as pushFileLogsToProxy: user_id MUST be auth.uid()
// (session user id) and organization_id is retrieved from public.users.
export async function pushPromptEventsToProxy(opts?: { limit?: number }): Promise<{
  ok: boolean;
  pushed: number;
  skipped: number;
  error?: string;
}> {
  try {
    const session = await getSession();
    if (!session?.user) return { ok: false, pushed: 0, skipped: 0, error: "Not signed in" };
    const user_id = session.user.id; // auth.uid() — RLS requires this exact value

    const { data: userRow } = await supabase
      .from("users")
      .select("organization_id")
      .eq("id", user_id)
      .maybeSingle();
    const organization_id = userRow?.organization_id ?? null;
    console.log("[Supabase] pushPrompts user_id:", user_id, "| organization_id:", organization_id);
    await supabaseLog(`[prompts.log] user_id=${user_id} organization_id=${organization_id}`);

    const { invoke } = await import("@tauri-apps/api/core");
    const events = await invoke<any[]>("get_prompt_events", { limit: opts?.limit ?? 200 });
    const prompts = (events || []).filter((e) => e.event === "prompt_redact");
    await supabaseLog(`[prompts.log] read ${(events || []).length} prompt_events, ${prompts.length} prompt_redact rows`);
    if (prompts.length === 0) return { ok: true, pushed: 0, skipped: 0 };

    // Dedupe: skip rows already present for this user (same flow_id + label + ts)
    const { data: existing } = await supabase
      .from("proxy_logs")
      .select("flow_id, label, ts")
      .eq("user_id", user_id)
      .in("flow_id", prompts.map((e) => e.flow_id).filter(Boolean));
    const seen = new Set(
      (existing || []).map((r) => `${r.flow_id}|${r.label}|${r.ts}`)
    );
    const fresh = prompts.filter(
      (e) => !seen.has(`${e.flow_id}|${e.label}|${e.ts}`)
    );
    const skipped = prompts.length - fresh.length;
    if (fresh.length === 0) return { ok: true, pushed: 0, skipped };

    const rows = fresh.map((ev) => ({
      user_id,
      organization_id,
      flow_id: ev.flow_id,
      event_type: "text_redact" as const,
      endpoint: ev.url,
      content_type: ev.content_type,
      entities: ev.entities ?? [],
      pii_count: ev.pii_count ?? 0,
      pii_preview: ev.pii_preview ?? [],
      text_len: ev.original_len,
      redacted: (ev.pii_count ?? 0) > 0,
      label: ev.label,
      original_content: ev.original ?? null,
      transformed_content: ev.redacted ?? null,
      ts: ev.ts,
    }));

    // Terminal debug: show exactly what is about to be sent
    await supabaseLog(`[prompts.log] SENDING ${rows.length} rows (skipped ${skipped})`);
    for (const r of rows.slice(0, 5)) {
      const orig = (r.original_content ?? "").slice(0, 60).replace(/\n/g, " ");
      const trans = (r.transformed_content ?? "").slice(0, 60).replace(/\n/g, " ");
      await supabaseLog(
        `  text_redact flow=${r.flow_id} label=${r.label ?? ""} pii=${r.pii_count} ` +
        `orig="${orig}" -> trans="${trans}"`
      );
    }
    if (rows.length > 5) await supabaseLog(`  ... and ${rows.length - 5} more`);

    const { error } = await supabase.from("proxy_logs").insert(rows);
    if (error) {
      console.error("[Supabase] pushPrompts insert error:", error);
      await supabaseLog(`[prompts.log] INSERT ERROR: ${error.message}`);
      return { ok: false, pushed: 0, skipped, error: error.message };
    }
    console.log(`[Supabase] pushPrompts pushed ${rows.length} rows (skipped ${skipped})`);
    await supabaseLog(`[prompts.log] INSERT OK: ${rows.length} rows pushed (skipped ${skipped})`);
    return { ok: true, pushed: rows.length, skipped };
  } catch (e) {
    console.error("[Supabase] pushPrompts error:", e);
    return { ok: false, pushed: 0, skipped: 0, error: String(e) };
  }
}

// ── Combined: files.log + prompts.log → proxy_logs ──────────
export async function pushProxyLogsToSupabase(opts?: { limit?: number }) {
  await supabaseLog("pushProxyLogsToSupabase START");
  const files = await pushFileLogsToProxy(opts);
  const prompts = await pushPromptEventsToProxy(opts);
  await supabaseLog(
    `pushProxyLogsToSupabase DONE — files: ${files.ok ? files.pushed : "ERR:" + files.error} ` +
    `(skipped ${files.skipped}), prompts: ${prompts.ok ? prompts.pushed : "ERR:" + prompts.error} ` +
    `(skipped ${prompts.skipped})`
  );
  return { files, prompts };
}
