/**
 * Dropvault — Dashboard Plugin (N-vault)
 *
 * Secret drop-in UI backed by Vaultwarden. Lists env-var secret
 * names (never values), and offers a form to add/update one secret.
 * Talks to /api/plugins/dropvault/.
 *
 * Multi-vault: on load GET /vaults; one vault renders exactly the
 * legacy single-vault UI (vault id passed silently); N vaults render
 * a tab/pill switcher with per-vault lock dots, unlock forms, and
 * secret lists. All calls carry the selected vault id
 * (GET ?vid=, POST {vault: id}); POST /sync-env stays global.
 * Falls back to the legacy no-vault calls if /vaults 404s (old backend).
 *
 * Plain IIFE, no build step. Uses window.__HERMES_PLUGIN_SDK__.
 */
(function () {
  "use strict";

  const SDK = window.__HERMES_PLUGIN_SDK__;
  if (!SDK) return;

  const { React } = SDK;
  const h = React.createElement;
  const {
    Card, CardContent,
    Badge, Button, Input, Label,
  } = SDK.components;
  const { useState, useEffect, useCallback } = SDK.hooks;
  const { cn } = SDK.utils;

  const API = "/api/plugins/dropvault";

  function api(path, opts) {
    return fetch(API + path, Object.assign({
      headers: { "Content-Type": "application/json" },
      credentials: "include",
    }, opts)).then(async (r) => {
      const body = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(body.detail || r.statusText);
      return body;
    });
  }

  // GET helper: appends ?vid= unless vid is null (legacy backend mode).
  function apiGet(path, vid) {
    if (vid === null || vid === undefined) return api(path);
    const sep = path.indexOf("?") === -1 ? "?" : "&";
    return api(path + sep + "vid=" + encodeURIComponent(vid));
  }

  // POST helper: merges {vault: id} into the JSON body unless legacy mode.
  function apiPost(path, vid, payload, opts) {
    const body = Object.assign({}, payload);
    if (vid !== null && vid !== undefined) body.vault = vid;
    return api(path, Object.assign({ method: "POST", body: JSON.stringify(body) }, opts));
  }

  // Small inline spinner (currentColor), sized via className.
  function Spinner({ className }) {
    return h("svg", {
      className: cn("animate-spin", className || "h-4 w-4"),
      viewBox: "0 0 24 24", fill: "none",
      "aria-hidden": "true",
    }, h("circle", {
      className: "opacity-25", cx: "12", cy: "12", r: "10",
      stroke: "currentColor", strokeWidth: "4",
    }), h("path", {
      className: "opacity-75", fill: "currentColor",
      d: "M4 12a8 8 0 0 1 8-8v4a4 4 0 0 0-4 4H4z",
    }));
  }

  // Lock-state dot: green = unlocked, red = locked/unknown.
  function LockDot({ ok }) {
    return h("span", {
      className: cn("inline-block h-2 w-2 rounded-full shrink-0",
        ok ? "bg-emerald-500" : "bg-red-500"),
      "aria-label": ok ? "unlocked" : "locked",
      title: ok ? "unlocked" : "locked",
    });
  }

  function App() {
    // vaults: null = loading, [] = legacy backend (no /vaults route),
    // else [{id, label, ok, vault, email, server, folder}]
    const [vaults, setVaults] = useState(null);
    const [sel, setSel] = useState(null);
    // Per-vault state, keyed by vault id.
    const [statusBy, setStatusBy] = useState({});
    const [secretsBy, setSecretsBy] = useState({});
    const [errorBy, setErrorBy] = useState({});
    const [noticeBy, setNoticeBy] = useState({});
    const [pwBy, setPwBy] = useState({});
    // Two-step login state, per vault: null = no 2FA challenge pending,
    // else {methods: [{id, name}], method: id|null, code: ""}.
    const [tfaBy, setTfaBy] = useState({});
    const [legacyTfa, setLegacyTfa] = useState(null);
    // Legacy single-vault state (used only when /vaults 404s).
    const [legacyStatus, setLegacyStatus] = useState(null);
    const [legacySecrets, setLegacySecrets] = useState(null);
    const [legacyError, setLegacyError] = useState(null);
    const [legacyNotice, setLegacyNotice] = useState(null);
    const [legacyPw, setLegacyPw] = useState("");
    // Shared form / busy state (reset on vault switch).
    const [name, setName] = useState("");
    const [value, setValue] = useState("");
    const [busy, setBusy] = useState(false);
    const [unlocking, setUnlocking] = useState(false);
    const [showForm, setShowForm] = useState(false);
    const [editName, setEditName] = useState(null);
    // Vault add/edit/remove dialog state.
    const [manageOpen, setManageOpen] = useState(false); // false | "add" | {mode:"edit", id}
    const [mId, setMId] = useState("");
    const [mLabel, setMLabel] = useState("");
    const [mEmail, setMEmail] = useState("");
    const [mServer, setMServer] = useState("");
    const [mFolder, setMFolder] = useState(""); // legacy back-compat (optional)
    const [mCollection, setMCollection] = useState("");
    const [mCa, setMCa] = useState("");
    // Remount key for the add/edit form: bumped on every open so the
    // dialog identity stays stable (no focus jumps) yet inputs reset.
    const [manageKey, setManageKey] = useState(0);
    // One-shot autofocus for the ID field on open (ref callback fires on
    // mount only — no autoFocus prop, which can re-fire on re-renders).
    const idAutofocusRef = useCallback((el) => {
      if (el && typeof el.focus === "function") {
        try { el.focus({ preventScroll: true }); } catch (e) { try { el.focus(); } catch (e2) {} }
      }
    }, []);
    const [mBusy, setMBusy] = useState(false);
    const [mError, setMError] = useState(null);
    const [confirmRemove, setConfirmRemove] = useState(null); // vault id | null
    // Collapsed vault cards, keyed by id. Persisted to localStorage so the
    // layout survives reloads.
    const [collapsedBy, setCollapsedBy] = useState(() => {
      try {
        const raw = (typeof localStorage !== "undefined" && localStorage.getItem("dropvault.collapsed")) || "{}";
        const parsed = JSON.parse(raw);
        return parsed && typeof parsed === "object" ? parsed : {};
      } catch (e) { return {}; }
    });
    function setCollapsed(id, val) {
      setCollapsedBy((m) => {
        const next = Object.assign({}, m);
        if (val) next[id] = true; else delete next[id];
        try { if (typeof localStorage !== "undefined") localStorage.setItem("dropvault.collapsed", JSON.stringify(next)); } catch (e) {}
        return next;
      });
    }

    const legacy = vaults !== null && vaults.length === 0;
    const multi = !legacy && vaults !== null && vaults.length > 1;
    const status = legacy ? legacyStatus : (sel ? statusBy[sel] || null : null);
    const secrets = legacy ? legacySecrets : (sel ? secretsBy[sel] || null : null);
    const error = legacy ? legacyError : (sel ? errorBy[sel] || null : null);
    const notice = legacy ? legacyNotice : (sel ? noticeBy[sel] || null : null);
    const pw = legacy ? legacyPw : (sel ? (pwBy[sel] || "") : "");
    const setPw = legacy
      ? setLegacyPw
      : (v) => setPwBy((m) => Object.assign({}, m, { [sel]: v }));
    const setError = legacy
      ? setLegacyError
      : (v) => setErrorBy((m) => Object.assign({}, m, { [sel]: v }));
    const setNotice = legacy
      ? setLegacyNotice
      : (v) => setNoticeBy((m) => Object.assign({}, m, { [sel]: v }));
    // 2FA challenge for the selected vault (null = none pending).
    const tfa = legacy ? legacyTfa : (sel ? tfaBy[sel] || null : null);
    const setTfa = legacy
      ? setLegacyTfa
      : (v) => setTfaBy((m) => Object.assign({}, m, { [sel]: v }));

    // Effective vault id for API calls: null in legacy mode.
    const vid = legacy ? null : sel;

    const refreshOne = useCallback(async (id) => {
      if (id === null) {
        // Legacy backend: unsuffixed routes.
        setLegacyError(null);
        try {
          const st = await api("/status");
          setLegacyStatus(st);
          if (st.ok) {
            setLegacySecrets(null);
            const s = await api("/secrets");
            setLegacySecrets(s.secrets);
          } else {
            setLegacySecrets(null);
          }
        } catch (e) {
          setLegacyError(e.message);
        }
        return;
      }
      setErrorBy((m) => Object.assign({}, m, { [id]: null }));
      try {
        const st = await apiGet("/status", id);
        setStatusBy((m) => Object.assign({}, m, { [id]: st }));
        if (st.ok) {
          // Show loading skeleton while the folder decrypts.
          setSecretsBy((m) => Object.assign({}, m, { [id]: null }));
          const s = await apiGet("/secrets", id);
          setSecretsBy((m) => Object.assign({}, m, { [id]: s.secrets }));
        } else {
          setSecretsBy((m) => Object.assign({}, m, { [id]: null }));
        }
      } catch (e) {
        setErrorBy((m) => Object.assign({}, m, { [id]: e.message }));
      }
    }, []);

    // Refresh the /vaults roster (lock dots) without wiping per-vault data.
    const refreshVaults = useCallback(async () => {
      try {
        const v = await api("/vaults");
        const list = v.vaults || v;
        setVaults(list);
        return list;
      } catch (e) {
        if (/not found|404/i.test(e.message || "")) {
          setVaults([]); // legacy backend
          return [];
        }
        throw e;
      }
    }, []);

    const refresh = useCallback(async () => {
      try {
        const list = await refreshVaults();
        if (list.length === 0) {
          await refreshOne(null);
        } else {
          // Keep selection stable; default to first unlocked, else first.
          setSel((cur) => {
            const ids = list.map((x) => x.id);
            if (cur && ids.indexOf(cur) !== -1) { refreshOne(cur); return cur; }
            const unlocked = list.find((x) => x.ok);
            const next = (unlocked || list[0]).id;
            refreshOne(next);
            return next;
          });
        }
      } catch (e) {
        // /vaults itself failed (gateway down?): surface globally on selection.
        setVaults([]);
        setLegacyError(e.message);
      }
    }, [refreshOne, refreshVaults]);

    useEffect(() => { refresh(); }, [refresh]);

    function selectVault(id) {
      if (id === sel) return;
      // Reset shared form state so drafts never leak across vaults.
      // (2FA challenges stay keyed per vault — switching away and back
      // keeps the pending challenge, not the password.)
      setShowForm(false); setEditName(null); setName(""); setValue("");
      setUnlocking(false); setBusy(false);
      setSel(id);
      // Lazily load vaults never opened this session.
      if (statusBy[id] === undefined) refreshOne(id);
    }

    // Unlock, with auto-detect two-step login: first attempt is plain
    // password; a 402 "two-factor required" response with the server's
    // methods list flips the form into code-entry mode and the retry
    // carries {password, method, code}.
    async function doUnlock(e) {
      e.preventDefault();
      setUnlocking(true); setError(null);
      try {
        const payload = { password: pw };
        if (tfa && tfa.code) {
          payload.code = tfa.code;
          if (tfa.method !== null && tfa.method !== undefined) payload.method = tfa.method;
        }
        let resp = null;
        try {
          resp = await apiPost("/unlock", vid, payload);
        } catch (err) {
          // api() throws on !ok with body.detail as the message; recover
          // the parsed body for the 402 branch via a raw fetch.
          if (!/two-factor required/i.test(err.message || "")) throw err;
          const raw = await fetch(API + "/unlock", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify(Object.assign({ vault: vid }, payload)),
          }).then((r) => r.json().catch(() => ({})));
          if (!raw.methods || !raw.methods.length) throw err;
          const first = raw.methods[0].id;
          setTfa({ methods: raw.methods, method: first, code: "" });
          setError(null);
          setNotice("This account has two-step login — enter the code from your authenticator (or email), then Unlock again.");
          return;
        }
        void resp;
        setPw(""); setTfa(null);
        // Reveal the vault contents after a successful unlock.
        try { if (vid) setCollapsed(vid, false); } catch (e3) {}
        await refreshOne(vid);
        await refreshVaults().catch(() => {});
      } catch (e2) {
        setError(e2.message);
      } finally { setUnlocking(false); }
    }

    async function doLock() {
      setBusy(true);
      try {
        await apiPost("/lock", vid, {});
        await refreshOne(vid);
        await refreshVaults().catch(() => {});
      } finally { setBusy(false); }
    }

    async function doSync() {
      setBusy(true); setNotice(null);
      try {
        await apiPost("/sync", vid, {});
        setNotice("Vault cache synced from the server. Add or update secrets, then press Sync env to push them into the running tools.");
        await refreshOne(vid);
      } catch (e) {
        setError(e.message);
      } finally { setBusy(false); }
    }

    async function doSyncEnv() {
      setBusy(true); setNotice(null);
      try {
        // Global: gateway-wide re-apply, no vault scoping.
        await api("/sync-env", { method: "POST", body: "{}" });
        setNotice("Sync requested — the gateway applies vault secrets to its environment (and file shims) within ~5 seconds.");
        await refreshOne(vid);
      } catch (e) {
        setError(e.message);
      } finally { setBusy(false); }
    }

    // ---- Vault roster management (add / edit / remove / enable) ----
    function openAddVault() {
      setMId(""); setMLabel(""); setMEmail("");
      setMServer("https://"); setMFolder(""); setMCollection("");
      setMCa(""); setMError(null); setManageKey((k) => k + 1); setManageOpen("add");
    }
    function openEditVault(v) {
      setMId(v.id); setMLabel(v.label && v.label !== v.id ? v.label : "");
      setMEmail(v.email || ""); setMServer(v.server || "");
      setMFolder(v.folder || ""); setMCollection(v.collection || "");
      setMCa(""); setMError(null); setManageKey((k) => k + 1); setManageOpen({ mode: "edit", id: v.id });
    }
    function closeManage() {
      if (mBusy) return;
      setManageOpen(false); setMError(null); setConfirmRemove(null);
    }
    async function doSaveVault(e) {
      e.preventDefault();
      setMBusy(true); setMError(null);
      try {
        const payload = {
          id: mId.trim().toLowerCase(),
          label: mLabel.trim(), email: mEmail.trim(),
          server_url: mServer.trim(),
          folder: mFolder.trim(), collection: mCollection.trim(),
          ca_cert: mCa.trim(),
        };
        if (manageOpen === "add") {
          const r = await api("/vaults", { method: "POST", body: JSON.stringify(payload) });
          setManageOpen(false);
          setNotice(`Vault “${r.id}” added — unlock it to start pulling secrets.`);
          const list = await refreshVaults().catch(() => null);
          if (list) {
            setSel(r.id);
            await refreshOne(r.id);
          }
        } else {
          const id = manageOpen.id;
          await fetch(API + "/vaults/" + encodeURIComponent(id), {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify(payload),
          }).then(async (r) => {
            const body = await r.json().catch(() => ({}));
            if (!r.ok) throw new Error(body.detail || r.statusText);
            return body;
          });
          setManageOpen(false);
          setNotice(`Vault “${id}” updated — takes effect within seconds, no restart needed.`);
          await refreshVaults().catch(() => {});
          await refreshOne(id);
        }
      } catch (e2) {
        setMError(e2.message);
      } finally { setMBusy(false); }
    }
    async function doRemoveVault(id) {
      setMBusy(true); setMError(null);
      try {
        await fetch(API + "/vaults/" + encodeURIComponent(id), {
          method: "DELETE",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: "{}",
        }).then(async (r) => {
          const body = await r.json().catch(() => ({}));
          if (!r.ok) throw new Error(body.detail || r.statusText);
          return body;
        });
        setConfirmRemove(null); setManageOpen(false);
        setNotice(`Vault “${id}” removed — its session was forgotten.`);
        const list = await refreshVaults().catch(() => null);
        if (list && list.length) {
          const next = list[0].id;
          setSel(next);
          await refreshOne(next);
        }
      } catch (e2) {
        setMError(e2.message);
      } finally { setMBusy(false); }
    }
    async function doToggleVault(v) {
      setBusy(true);
      try {
        await fetch(API + "/vaults/" + encodeURIComponent(v.id), {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({ id: v.id, enabled: !(v.enabled !== false) }),
        }).then(async (r) => {
          const body = await r.json().catch(() => ({}));
          if (!r.ok) throw new Error(body.detail || r.statusText);
          return body;
        });
        await refreshVaults().catch(() => {});
        await refreshOne(v.id);
      } catch (e) {
        setError((multi && !legacy ? `Vault “${selLabel}”: ` : "") + e.message);
      } finally { setBusy(false); }
    }

    function openNew() {
      setEditName(null); setName(""); setValue("");
      setShowForm(true);
    }
    function openEdit(n) {
      setEditName(n); setName(n); setValue("");
      setShowForm(true);
    }

    async function doSave(e) {
      e.preventDefault();
      setBusy(true); setError(null);
      try {
        const r = await apiPost("/secrets", vid, { name, value });
        setNotice(r.created
          ? `Created ${r.name}.`
          : `Updated ${r.name}.`);
        setValue(""); setShowForm(false);
        await refreshOne(vid);
      } catch (e2) {
        setError(e2.message);
      } finally { setBusy(false); }
    }

    const selMeta = !legacy && sel
      ? (vaults || []).find((v) => v.id === sel) || null
      : null;
    const selLabel = legacy ? null : (selMeta && (selMeta.label || selMeta.id)) || sel;

    // Badge is rendered inside the vault card (VaultCard); the header no
    // longer shows lock state — HeaderButtons is global actions only.

    // 3 skeleton rows shown while the scope content decrypts/loads.
    function SecretSkeleton() {
      return h("div", { className: "py-2 space-y-2", "aria-busy": "true" },
        h("div", { className: "flex items-center gap-2 text-sm text-muted-foreground" },
          h(Spinner, { className: "h-3.5 w-3.5" }), "Decrypting vault contents…"),
        [64, 96, 80].map((w, i) =>
          h("div", { key: i, className: "flex items-center justify-between py-2" },
            h("div", { className: "h-4 rounded bg-muted animate-pulse", style: { width: w + "px" } }),
            h("div", { className: "h-4 w-14 rounded bg-muted animate-pulse" }))));
    }

    // Vault tab strip — rendered only when 2+ vaults exist, so a
    // single vault looks exactly like the legacy UI (plus one
    // vault counter button that opens management).
    function VaultTabs() {
      if (!multi) return null;
      return h("div", {
        key: "vaults",
        className: "flex flex-wrap gap-2",
        role: "tablist",
        "aria-label": "Vaults",
      }, vaults.map((v) => {
        const active = v.id === sel;
        // Prefer live per-vault status; fall back to the /vaults roster flag.
        const live = statusBy[v.id];
        const ok = live ? !!live.ok : !!v.ok;
        const enabled = v.enabled !== false;
        return h(Button, {
          key: v.id,
          role: "tab",
          "aria-selected": active ? "true" : "false",
          variant: active ? "default" : "outline",
          size: "sm",
          onClick: () => selectVault(v.id),
          className: "gap-2" + (enabled ? "" : " opacity-50"),
          title: [v.email, v.server, !enabled ? "disabled" : null].filter(Boolean).join(" · ") || v.id,
        }, h(LockDot, { ok }), v.label || v.id);
      }));
    }

    // Header: global actions only. Per-vault Lock/Sync live inside the
    // vault card below; the only per-vault thing here is the Vaults
    // counter that opens the add/edit/remove manager.
    function HeaderButtons() {
      const n = (!legacy && vaults) ? vaults.length : (status ? 1 : 0);
      const nb = "whitespace-nowrap";
      return h("div", { className: "flex items-center gap-2 flex-wrap" },
        status && status.ok && h(Button, { key: "se", variant: "outline", size: "sm", onClick: doSyncEnv, disabled: busy, className: nb },
          busy ? h(Spinner, { className: "h-3.5 w-3.5 mr-1.5" }) : null, "Sync env"),
        vaults !== null && h(Button, {
          key: "vaults", variant: "outline", size: "sm",
          onClick: openAddVault, disabled: busy, className: nb,
          title: n <= 1 ? "Add a vault" : `${n} vaults — add or manage`,
        }, `Vaults${n > 1 ? ` (${n})` : ""} +`));
    }

    // One self-contained vault section: identity, unlock form, actions,
    // and secrets all live inside this card, so Lock/Sync/secrets are
    // visually grouped with the vault they belong to. In multi mode the
    // tab strip above switches which vault is shown. Collapsible: the
    // identity row + connection line always show; everything below hides
    // when collapsed (persisted per vault id across reloads).
    function VaultCard() {
      const meta = legacy ? null : selMeta;
      const st = status;
      if (!meta && !st) return null;
      const cardId = meta ? meta.id : "legacy";
      const collapsed = !!collapsedBy[cardId];
      const label = meta ? (meta.label || meta.id) : "Vault";
      const enabled = !meta || meta.enabled !== false;
      const email = (meta && meta.email) || (st && st.email);
      const server = (meta && meta.server) || (st && st.server);
      // Scope: collection wins, else folder, else whole vault.
      const coll = (meta && meta.collection) || (st && st.collection) || "";
      const folder = (meta && meta.folder) || (st && st.folder) || "";
      const scopeClause = (coll ? `Collection “${coll}”` : folder ? `Folder “${folder}”` : "Whole vault")
        + (secrets ? ` · ${secrets.length} secrets` : "");
      const live = meta ? statusBy[meta.id] : null;
      const ok = live ? !!live.ok : (st ? !!st.ok : !!((meta && meta.ok)));
      const state = (st && st.vault) || (meta && meta.vault) || (ok ? "unlocked" : "locked");
      const nb = "whitespace-nowrap";
      const chev = h(Button, {
        key: "chev", variant: "ghost", size: "sm",
        onClick: () => setCollapsed(cardId, !collapsed),
        className: "h-7 w-7 px-0",
        title: collapsed ? "Expand vault" : "Collapse vault",
        "aria-expanded": collapsed ? "false" : "true",
        "aria-label": collapsed ? "Expand vault" : "Collapse vault",
      }, h("span", {
        className: "inline-block transition-transform " + (collapsed ? "" : "rotate-90"),
        "aria-hidden": "true",
      }, "›"));
      const head = h("div", { className: "flex items-center gap-2 flex-wrap" },
        chev,
        h(LockDot, { ok }),
        h("span", { className: "font-medium" }, label),
        ok ? h(Badge, { key: "b" }, "unlocked")
           : h(Badge, { key: "b", variant: "destructive" }, state),
        !enabled && h(Badge, { key: "d", variant: "outline" }, "disabled"),
        h("span", { className: "flex-1", key: "sp" }),
        meta && h(Button, {
          key: "edit", variant: "ghost", size: "sm",
          onClick: () => openEditVault(meta), disabled: busy,
          className: "h-7 px-2 text-xs whitespace-nowrap",
        }, "Edit"),
        meta && h(Button, {
          key: "toggle", variant: "ghost", size: "sm",
          onClick: () => doToggleVault(meta), disabled: busy,
          className: "h-7 px-2 text-xs whitespace-nowrap",
          title: enabled ? "Stop pulling secrets from this vault" : "Resume pulling secrets from this vault",
        }, enabled ? "Disable" : "Enable"));
      const conn = (email || server) && h("p", { key: "conn", className: "text-sm text-muted-foreground" },
        [email, server].filter(Boolean).join(" · "));
      if (collapsed) {
        return h(Card, { key: "vcard" },
          h(CardContent, { className: "py-4 space-y-2" }, head, conn));
      }
      const unlockForm = st && !st.ok && h("form", { key: "unlock", onSubmit: doUnlock, className: "flex gap-2 items-end flex-wrap" },
        h("div", { className: "flex-1 space-y-3 min-w-52" },
          h("div", { key: "pw" },
            h(Label, null, multi && !legacy ? `Master password — vault “${selLabel}”` : "Master password"),
            h(Input, { type: "password", value: pw, onChange: (e) => setPw(e.target.value),
                       placeholder: "vault master password", autoFocus: !tfa, disabled: unlocking })),
          tfa && h("div", { key: "tfa", className: "flex gap-2 items-end" },
            h("div", null,
              h(Label, null, "Method"),
              h("select", {
                value: tfa.method, disabled: unlocking,
                onChange: (e) => setTfa(Object.assign({}, tfa, { method: Number(e.target.value) })),
                className: "h-9 rounded-md border border-input bg-background px-2 text-sm",
                "aria-label": "Two-step login method",
              }, tfa.methods.map((m) =>
                h("option", { key: m.id, value: m.id }, m.name)))),
            h("div", { className: "flex-1" },
              h(Label, null, "Two-step code"),
              h(Input, {
                value: tfa.code, inputMode: "numeric", autoComplete: "one-time-code",
                autoFocus: true, disabled: unlocking,
                onChange: (e) => setTfa(Object.assign({}, tfa, { code: e.target.value.replace(/\s+/g, "") })),
                placeholder: tfa.method === 1 ? "emailed code" : "6-digit code",
              })))),
        h(Button, { type: "submit", disabled: unlocking || !pw || !!(tfa && !tfa.code), className: nb },
          unlocking && h(Spinner, { className: "h-4 w-4 mr-2" }),
          unlocking ? "Unlocking…" : tfa ? "Verify & unlock" : "Unlock"));
      const cliHint = st && !st.cli && h("p", { key: "cli", className: "text-sm" },
        "The bw CLI is not installed on this host. Install with: npm install -g @bitwarden/cli");
      // actions + secrets (this vault only)
      const actionRow = st && st.ok && h("div", { key: "actions", className: "flex items-center gap-2 flex-wrap" },
        h(Button, { variant: "outline", size: "sm", onClick: doLock, disabled: busy, className: nb },
          busy ? h(Spinner, { className: "h-3.5 w-3.5 mr-1.5" }) : null, "Lock"),
        h(Button, { variant: "outline", size: "sm", onClick: doSync, disabled: busy, className: nb },
          busy ? h(Spinner, { className: "h-3.5 w-3.5 mr-1.5" }) : null, "Sync"),
        h("span", { className: "text-xs text-muted-foreground" }, scopeClause));
      const secretForm = st && st.ok && showForm && h("form", { key: "form", onSubmit: doSave, className: "space-y-3 border-t pt-3" },
        h("div", null,
          h(Label, null, "Name (env var)"),
          h(Input, { value: name, onChange: (e) => setName(e.target.value.toUpperCase()),
                     placeholder: "OPENROUTER_API_KEY", disabled: !!editName, autoFocus: true })),
        h("div", null,
          h(Label, null, editName ? `New value for ${editName} (leave blank to keep current)` : "Value"),
          h(Input, { type: "text", value: value, onChange: (e) => setValue(e.target.value),
                     placeholder: editName ? "(unchanged — leave blank to keep)" : "secret value" })),
        h("div", { className: "flex gap-2 justify-end" },
          h(Button, { type: "button", variant: "ghost", onClick: () => setShowForm(false) }, "Cancel"),
          h(Button, { type: "submit", disabled: busy || !name || (!editName && !value) },
            busy && h(Spinner, { className: "h-4 w-4 mr-2" }),
            editName ? "Update" : "Create")));
      const loadingRow = st && st.ok && secrets === null && h("div", { key: "load", className: "py-2" }, SecretSkeleton());
      const secretList = st && st.ok && secrets && (secrets.length === 0
        ? h("p", { key: "empty", className: "text-sm text-muted-foreground py-4 text-center" },
            "No secrets yet. Add one — it becomes an environment variable for Hermes tools.")
        : h("div", { key: "list" },
            h("div", { className: "flex items-center justify-end pb-1" },
              h(Button, { size: "sm", onClick: openNew, disabled: busy, className: nb }, "Add secret")),
            h("ul", { className: "divide-y" },
              secrets.map((s) =>
                h("li", { key: s.name, className: "flex items-center justify-between py-2" },
                  h("span", { className: "text-sm" }, s.name),
                  h("div", { className: "flex items-center gap-2" },
                    h(Button, { variant: "ghost", size: "sm", onClick: () => openEdit(s.name), key: "e" }, "Update")))))));
      return h(Card, { key: "vcard" },
        h(CardContent, { className: "py-4 space-y-4" }, head, conn, unlockForm, cliHint,
          actionRow, secretForm, loadingRow, secretList));
    }

    // Add/edit vault dialog + remove confirmation.
    // NOTE: this must be called unconditionally (hooks + stable DOM
    // identity). openAddVault/openEditVault reset a `manageKey` so the
    // form remounts fresh per open, instead of unmounting modules.
    function ManageDialog() {
      const isAdd = manageOpen === "add";
      const idInput = isAdd
        ? h("div", null,
            h(Label, null, "ID (lowercase, digits, underscore)"),
            h(Input, {
              value: mId, onChange: (e) => setMId(e.target.value.toLowerCase().replace(/[^a-z0-9_]/g, "")),
              placeholder: "primary", disabled: mBusy,
              ref: idAutofocusRef,
            }))
        : h("div", null,
            h(Label, null, "ID"),
            h(Input, { value: (manageOpen && manageOpen.id) || "", disabled: true }));
      const removeZone = !isAdd && manageOpen && h("div", { className: "border-t pt-3 mt-1" },
        confirmRemove !== manageOpen.id
          ? h(Button, {
              variant: "ghost", size: "sm", disabled: mBusy,
              onClick: () => setConfirmRemove(manageOpen.id),
              className: "text-destructive",
            }, "Remove this vault…")
          : h("div", { className: "space-y-2" },
              h("p", { className: "text-sm text-muted-foreground" },
                `Remove vault “${manageOpen.id}”? Its session is forgotten; local CLI cache is kept so re-adding resumes instantly.`),
              h("div", { className: "flex gap-2 justify-end" },
                h(Button, { variant: "ghost", size: "sm", disabled: mBusy, onClick: () => setConfirmRemove(null) }, "Keep"),
                h(Button, {
                  variant: "destructive", size: "sm", disabled: mBusy,
                  onClick: () => doRemoveVault(manageOpen.id),
                }, mBusy && h(Spinner, { className: "h-4 w-4 mr-2" }), "Remove vault"))));
      if (!manageOpen) return null;
      return h(Card, { key: "manage" + manageKey },
        h(CardContent, { className: "py-4" },
          h("form", { onSubmit: doSaveVault, className: "space-y-3" },
            h("h2", { className: "text-lg font-medium" },
              isAdd ? "Add a vault" : `Edit vault “${manageOpen.id}”`),
            h("p", { className: "text-sm text-muted-foreground" },
              isAdd
                ? "Point at any reachable Vaultwarden / Bitwarden server — no local container needed. Unlock it next to start pulling secrets."
                : "Connection fields only — sessions and secrets are never touched here."),
            mError && h("p", { className: "text-sm text-destructive" }, mError),
            idInput,
            h("div", null,
              h(Label, null, "Label (display name, optional)"),
              h(Input, { value: mLabel, onChange: (e) => setMLabel(e.target.value), placeholder: "Family vault", disabled: mBusy })),
            h("div", null,
              h(Label, null, "Account email"),
              h(Input, { value: mEmail, onChange: (e) => setMEmail(e.target.value), placeholder: "you@example.com", disabled: mBusy })),
            h("div", null,
              h(Label, null, "Server URL"),
              h(Input, {
                value: mServer, onChange: (e) => setMServer(e.target.value),
                placeholder: "https://vault.example.com", disabled: mBusy,
              })),
            h("div", null,
              h(Label, null, "Collection (optional — needs an org; whole vault when empty)"),
              h(Input, { value: mCollection, onChange: (e) => setMCollection(e.target.value), placeholder: "hermes", disabled: mBusy }),
              h("p", { className: "text-xs text-muted-foreground pt-1" },
                "Bitwarden items an org tags for Hermes. Wins over Folder; best for big vaults.")),
            h("div", { className: "flex gap-2" },
              h("div", { className: "flex-1" },
                h(Label, null, "Folder (legacy, optional)"),
                h(Input, { value: mFolder, onChange: (e) => setMFolder(e.target.value), placeholder: "leave empty", disabled: mBusy })),
              h("div", { className: "flex-1" },
                h(Label, null, "CA cert (self-signed only)"),
                h(Input, { value: mCa, onChange: (e) => setMCa(e.target.value), placeholder: "omit for public HTTPS", disabled: mBusy }))),
            h("div", { className: "flex gap-2 justify-end" },
              h(Button, { type: "button", variant: "ghost", onClick: closeManage, disabled: mBusy }, "Cancel"),
              h(Button, {
                type: "submit",
                disabled: mBusy || (isAdd && (!mId.trim() || mServer.trim() === "" || mServer.trim() === "https://")),
              }, mBusy && h(Spinner, { className: "h-4 w-4 mr-2" }), isAdd ? "Add vault" : "Save")),
            removeZone)));
    }

    return h("div", { className: "p-6 space-y-6 max-w-3xl mx-auto" },
      // header
      h("div", { className: "flex items-center justify-between" },
        h("div", null,
          h("h1", { className: "text-2xl font-semibold" }, "Dropvault"),
          h("p", { className: "text-sm text-muted-foreground" },
            multi
              ? `Secrets in ${vaults.length} Vaultwarden vaults — values never enter chat or logs.`
              : "Secrets in the local Vaultwarden — values never enter chat or logs.")),
        h(HeaderButtons)),

      h(VaultTabs),

      h(VaultCard),
      h(ManageDialog),

      error && h(Card, { key: "err" }, h(CardContent, { className: "text-sm text-destructive py-3" },
        multi && !legacy ? `Vault “${selLabel}”: ${error}` : error)),
      notice && h(Card, { key: "ok" }, h(CardContent, { className: "text-sm text-muted-foreground py-3" }, notice)),

      // initial status check
      !status && !error && h(Card, { key: "st" },
        h(CardContent, { className: "py-6 flex items-center justify-center gap-2 text-sm text-muted-foreground" },
          h(Spinner, { className: "h-4 w-4" }), "Checking vault status…")));
  }

  if (window.__HERMES_PLUGINS__ && typeof window.__HERMES_PLUGINS__.register === "function") {
    window.__HERMES_PLUGINS__.register("dropvault", App);
  }
})();
