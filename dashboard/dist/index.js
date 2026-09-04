/**
 * Dropvault — Dashboard Plugin
 *
 * Secret drop-in UI backed by the local Vaultwarden. Lists env-var secret
 * names (never values), and offers a form to add/update one secret.
 * Talks to /api/plugins/dropvault/.
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
    Badge, Button, Input, Label, Textarea,
  } = Object.assign(
    {},
    SDK.components,
    { Textarea: SDK.components.Textarea || "textarea" }
  );
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

  function App() {
    const [status, setStatus] = useState(null);
    const [secrets, setSecrets] = useState(null);
    const [error, setError] = useState(null);
    const [notice, setNotice] = useState(null);
    const [pw, setPw] = useState("");
    const [name, setName] = useState("");
    const [value, setValue] = useState("");
    const [notes, setNotes] = useState("");
    const [busy, setBusy] = useState(false);
    const [unlocking, setUnlocking] = useState(false);
    const [showForm, setShowForm] = useState(false);
    const [editName, setEditName] = useState(null);

    const refresh = useCallback(async () => {
      setError(null);
      try {
        const st = await api("/status");
        setStatus(st);
        if (st.ok) {
          setSecrets(null); // show loading skeleton while the folder decrypts
          const s = await api("/secrets");
          setSecrets(s.secrets);
        } else {
          setSecrets(null);
        }
      } catch (e) {
        setError(e.message);
      }
    }, []);

    useEffect(() => { refresh(); }, [refresh]);

    async function doUnlock(e) {
      e.preventDefault();
      setUnlocking(true); setError(null);
      try {
        await api("/unlock", { method: "POST", body: JSON.stringify({ password: pw }) });
        setPw("");
        await refresh();
      } catch (e2) {
        setError(e2.message);
      } finally { setUnlocking(false); }
    }

    async function doLock() {
      setBusy(true);
      try {
        await api("/lock", { method: "POST", body: "{}" });
        await refresh();
      } finally { setBusy(false); }
    }

    async function doSync() {
      setBusy(true); setNotice(null);
      try {
        await api("/sync", { method: "POST", body: "{}" });
        setNotice("Vault synced. New secrets are picked up on next Hermes restart (or by the source re-pull).");
        await refresh();
      } catch (e) {
        setError(e.message);
      } finally { setBusy(false); }
    }

    function openNew() {
      setEditName(null); setName(""); setValue(""); setNotes("");
      setShowForm(true);
    }
    function openEdit(n) {
      setEditName(n); setName(n); setValue(""); setNotes("");
      setShowForm(true);
    }

    async function doSave(e) {
      e.preventDefault();
      setBusy(true); setError(null);
      try {
        const r = await api("/secrets", {
          method: "POST",
          body: JSON.stringify({ name, value, notes: notes || null }),
        });
        setNotice(r.created
          ? `Created ${r.name}.`
          : `Updated ${r.name}.`);
        setValue(""); setNotes(""); setShowForm(false);
        await refresh();
      } catch (e2) {
        setError(e2.message);
      } finally { setBusy(false); }
    }

    const statusBadge = !status ? h(Spinner, { className: "h-4 w-4 text-muted-foreground" }) :
      status.ok ? h(Badge, { key: "b" }, "unlocked") :
      h(Badge, { key: "b", variant: "destructive" }, status.vault);

    // 3 skeleton rows shown while the folder content decrypts/loads.
    function SecretSkeleton() {
      return h("div", { className: "py-2 space-y-2", "aria-busy": "true" },
        h("div", { className: "flex items-center gap-2 text-sm text-muted-foreground" },
          h(Spinner, { className: "h-3.5 w-3.5" }), "Decrypting folder contents…"),
        [64, 96, 80].map((w, i) =>
          h("div", { key: i, className: "flex items-center justify-between py-2" },
            h("div", { className: "h-4 rounded bg-muted animate-pulse", style: { width: w + "px" } }),
            h("div", { className: "h-4 w-14 rounded bg-muted animate-pulse" }))));
    }

    return h("div", { className: "p-6 space-y-6 max-w-3xl mx-auto" },
      // header
      h("div", { className: "flex items-center justify-between" },
        h("div", null,
          h("h1", { className: "text-2xl font-semibold" }, "Dropvault"),
          h("p", { className: "text-sm text-muted-foreground" },
            "Secrets in the local Vaultwarden — values never enter chat or logs.")),
        h("div", { className: "flex items-center gap-2" }, statusBadge,
          status && status.ok && h(Button, { key: "l", variant: "outline", size: "sm", onClick: doLock, disabled: busy },
            busy ? h(Spinner, { className: "h-3.5 w-3.5 mr-1.5" }) : null, "Lock"),
          status && status.ok && h(Button, { key: "s", variant: "outline", size: "sm", onClick: doSync, disabled: busy },
            busy ? h(Spinner, { className: "h-3.5 w-3.5 mr-1.5" }) : null, "Sync"))),

      error && h(Card, { key: "err" }, h(CardContent, { className: "text-sm text-destructive py-3" }, error)),
      notice && h(Card, { key: "ok" }, h(CardContent, { className: "text-sm text-muted-foreground py-3" }, notice)),

      // initial status check
      !status && h(Card, { key: "st" },
        h(CardContent, { className: "py-6 flex items-center justify-center gap-2 text-sm text-muted-foreground" },
          h(Spinner, { className: "h-4 w-4" }), "Checking vault status…")),

      // unlock form
      status && !status.ok && h(Card, { key: "u" },
        h(CardContent, { className: "py-4" },
          h("form", { onSubmit: doUnlock, className: "flex gap-2 items-end" },
            h("div", { className: "flex-1" },
              h(Label, null, "Master password"),
              h(Input, { type: "password", value: pw, onChange: (e) => setPw(e.target.value),
                         placeholder: "vault master password", autoFocus: true, disabled: unlocking })),
            h(Button, { type: "submit", disabled: unlocking || !pw },
              unlocking && h(Spinner, { className: "h-4 w-4 mr-2" }),
              unlocking ? "Unlocking…" : "Unlock")))),

      status && !status.cli && h(Card, { key: "cli" },
        h(CardContent, { className: "py-3 text-sm" },
          "The bw CLI is not installed on this host. Install with: npm install -g @bitwarden/cli")),

      status && status.ok && h(React.Fragment, { key: "main" },
        h("div", { className: "flex items-center justify-between" },
          h("h2", { className: "text-lg font-medium" },
            `Secrets (${secrets ? secrets.length : "…"}) — folder "${status.folder}"`),
          h(Button, { size: "sm", onClick: openNew, disabled: busy }, "Add secret")),

        showForm && h(Card, { key: "form" },
          h(CardContent, { className: "py-4" },
            h("form", { onSubmit: doSave, className: "space-y-3" },
              h("div", null,
                h(Label, null, "Name (env var)"),
                h(Input, { value: name, onChange: (e) => setName(e.target.value.toUpperCase()),
                           placeholder: "OPENROUTER_API_KEY", disabled: !!editName, autoFocus: true })),
              h("div", null,
                h(Label, null, editName ? `New value for ${editName} (leave blank to keep current)` : "Value"),
                h(Input, { type: "password", value: value, onChange: (e) => setValue(e.target.value),
                           placeholder: editName ? "•••••• (unchanged)" : "secret value" })),
              h("div", null,
                h(Label, null, "Notes (optional, stored as item notes — not secret)"),
                h(Textarea, { rows: 2, value: notes, onChange: (e) => setNotes(e.target.value) })),
              h("div", { className: "flex gap-2 justify-end" },
                h(Button, { type: "button", variant: "ghost", onClick: () => setShowForm(false) }, "Cancel"),
                h(Button, { type: "submit", disabled: busy || !name || (!editName && !value) },
                  busy && h(Spinner, { className: "h-4 w-4 mr-2" }),
                  editName ? "Update" : "Create"))))),

        status.ok && secrets === null && h(Card, { key: "load" },
          h(CardContent, { className: "py-2" }, h(SecretSkeleton))),

        secrets && h(Card, { key: "list" },
          h(CardContent, { className: "py-2" },
            secrets.length === 0
              ? h("p", { className: "text-sm text-muted-foreground py-4 text-center" },
                  "No secrets yet. Add one — it becomes an environment variable for Hermes tools.")
              : h("ul", { className: "divide-y" },
                  secrets.map((s) =>
                    h("li", { key: s.name, className: "flex items-center justify-between py-2" },
                      // explicit foreground color — dashboard `code` styling is a
                      // multi-color gradient which is unreadable as a list label
                      h("code", { className: "text-sm font-mono text-foreground", style: { color: "var(--foreground)" } }, s.name),
                      h("div", { className: "flex items-center gap-2" },
                        s.has_notes && h(Badge, { variant: "outline", key: "n" }, "notes"),
                        h(Button, { variant: "ghost", size: "sm", onClick: () => openEdit(s.name), key: "e" }, "Update")))))))));
  }

  if (window.__HERMES_PLUGINS__ && typeof window.__HERMES_PLUGINS__.register === "function") {
    window.__HERMES_PLUGINS__.register("dropvault", App);
  }
})();
