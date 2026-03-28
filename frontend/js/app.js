/* ═══════════════════════════════════════════════
   BlogSphere — app.js  (shared utilities)
   ═══════════════════════════════════════════════ */

const API = "http://127.0.0.1:5000";   // ← change to your Flask URL

/* ── Token helpers ──────────────────────────── */
const Auth = {
  getAccess()  { return localStorage.getItem("access_token"); },
  getRefresh() { return localStorage.getItem("refresh_token"); },
  setTokens(a, r) {
    localStorage.setItem("access_token", a);
    if (r) localStorage.setItem("refresh_token", r);
  },
  clear() {
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
  },
  isLoggedIn() { return !!this.getAccess(); },
};

/* ── API fetch wrapper (auto-refresh) ────────── */
async function apiFetch(path, options = {}) {
  let headers = { ...(options.headers || {}) };
   if (!(options.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }

  if (Auth.getAccess()) headers["Authorization"] = `Bearer ${Auth.getAccess()}`;

  let res = await fetch(`${API}${path}`, { ...options, headers });

  // try token refresh on 401
  if (res.status === 401 && Auth.getRefresh()) {
    const refreshRes = await fetch(`${API}/refresh`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${Auth.getRefresh()}`,
      },
    });
    if (refreshRes.ok) {
      const d = await refreshRes.json();
      Auth.setTokens(d.access_token);
      headers["Authorization"] = `Bearer ${d.access_token}`;
      res = await fetch(`${API}${path}`, { ...options, headers });
    } else {
      Auth.clear();
      window.location.href= "/index.html";
      return;
    }
  }
  return res;
}

/* ── Toast ───────────────────────────────────── */
function toast(msg, type = "success") {
  let container = document.querySelector(".toast-container");
  if (!container) {
    container = document.createElement("div");
    container.className = "toast-container";
    document.body.appendChild(container);
  }
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => el.remove(), 3200);
}

/* ── Banner helpers ──────────────────────────── */
function showBanner(id, msg, type = "error") {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = `banner show-${type}`;
  el.textContent = msg;
}
function clearBanner(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = "banner";
  el.textContent = "";
}

/* ── Button loading state ────────────────────── */
function setLoading(btn, loading, label) {
  if (loading) {
    btn.dataset.origText = btn.textContent;
    btn.textContent = "";
    btn.classList.add("btn-loading");
  } else {
    btn.classList.remove("btn-loading");
    btn.textContent = label || btn.dataset.origText || "Submit";
  }
}

/* ── Password visibility toggle ─────────────── */
function togglePwd(inputId, btn) {
  const inp = document.getElementById(inputId);
  inp.type = inp.type === "password" ? "text" : "password";
  btn.textContent = inp.type === "password" ? "👁" : "🙈";
}

/* ── Password strength meter ─────────────────── */
function checkStrength(val, prefix = "st") {
  const segs  = [1,2,3,4].map(i => document.getElementById(`${prefix}${i}`));
  const label = document.getElementById(`${prefix}-label`);
  if (!segs[0]) return;
  let score = 0;
  if (val.length >= 8) score++;
  if (/[A-Z]/.test(val)) score++;
  if (/[0-9]/.test(val)) score++;
  if (/[^A-Za-z0-9]/.test(val)) score++;
  const colors = ["#ff5f6d","#fc8b2f","#f9e04b","#22d3a5"];
  const labels = ["Weak","Fair","Good","Strong"];
  segs.forEach((s, i) => {
    s.style.background = i < score ? colors[score - 1] : "var(--border)";
  });
  if (label) {
    label.textContent = val.length ? (labels[score - 1] || "") : "";
    label.style.color = score > 0 ? colors[score - 1] : "var(--muted)";
  }
}

/* ── OTP box helpers ─────────────────────────── */
function otpStep(input, idx, cls = "otp-digit") {
  const digits = document.querySelectorAll(`.${cls}`);
  const val = input.value.replace(/\D/g, "");
  input.value = val ? val[0] : "";
  if (input.value && idx < digits.length - 1) digits[idx + 1].focus();
  input.addEventListener("keydown", e => {
    if (e.key === "Backspace" && !input.value && idx > 0) digits[idx - 1].focus();
  }, { once: true });
}
function getOTP(cls = "otp-digit") {
  return Array.from(document.querySelectorAll(`.${cls}`)).map(i => i.value).join("");
}
function clearOTP(cls = "otp-digit") {
  document.querySelectorAll(`.${cls}`).forEach(i => i.value = "");
  document.querySelectorAll(`.${cls}`)[0]?.focus();
}

/* ── Countdown timer ─────────────────────────── */
function startTimer(spanId, btnId, seconds = 60) {
  const span = document.getElementById(spanId);
  const btn  = document.getElementById(btnId);
  if (!span) return;
  let s = seconds;
  span.textContent = s;
  if (btn) btn.style.display = "none";
  span.closest(".timer").style.display = "block";
  const iv = setInterval(() => {
    s--;
    span.textContent = s;
    if (s <= 0) {
      clearInterval(iv);
      span.closest(".timer").style.display = "none";
      if (btn) btn.style.display = "block";
    }
  }, 1000);
  return iv;
}

/* ── Navbar renderer ─────────────────────────── */
function renderNavbar(activePage = "") {
  const loggedIn = Auth.isLoggedIn();
  const nav = document.getElementById("navbar");
  if (!nav) return;

  nav.innerHTML = `
    <a href="index.html" class="nav-logo">
      <div class="nav-logo-icon">B</div>
      BlogSphere
    </a>
    <div class="nav-spacer"></div>
    <nav class="nav-links">
      <a href="index.html" class="nav-link ${activePage==='home'?'active':''}">Home</a>
      ${loggedIn ? `
        <a href="add_blog.html" class="nav-link ${activePage==='add'?'active':''}">✏️ Write</a>
        <a href="profile.html" class="nav-link ${activePage==='profile'?'active':''}">Profile</a>
        <button class="nav-btn btn-ghost" style="border:1px solid var(--border);color:var(--muted);background:var(--input-bg);padding:7px 14px;border-radius:10px;font-size:13px;" onclick="doLogout()">Logout</button>
      ` : `
        <a href="login.html" class="nav-link ${activePage==='login'?'active':''}">Sign In</a>
        <a href="register.html" class="nav-btn">Get Started</a>
      `}
    </nav>
  `;
}

/* ── Logout ──────────────────────────────────── */
async function doLogout() {
  try {
    await apiFetch("/logout", { method: "POST" });
  } catch (err) {
    console.log("API error:", err);
  }
  Auth.clear();
  toast("Logged out successfully", "info");
  window.location.href= "index.html";
}

/* ── Format date ─────────────────────────────── */
function fmtDate(str) {
  if (!str) return "";
  const d = new Date(str);
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

/* ── Truncate text ───────────────────────────── */
function truncate(str, n = 120) {
  return str && str.length > n ? str.slice(0, n) + "…" : str;
}

/* ── Initials from name ──────────────────────── */
function initials(name) {
  if (!name) return "?";
  return name.split(" ").map(w => w[0]).slice(0, 2).join("").toUpperCase();
}

/* ── Image URL helper ────────────────────────── */
function imgSrc(img) {
  if (!img) return null;
  if (img.startsWith("http")) return img;
  return `${API}/${img}`;
}

/* ── Confirm modal ───────────────────────────── */
function confirmModal(title, body, onConfirm) {
  const old = document.getElementById("__confirm-modal");
  if (old) old.remove();
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  overlay.id = "__confirm-modal";
  overlay.innerHTML = `
    <div class="modal slide-up">
      <div class="modal-title">${title}</div>
      <div class="modal-body">${body}</div>
      <div class="modal-actions">
        <button class="btn btn-ghost" onclick="document.getElementById('__confirm-modal').remove()">Cancel</button>
        <button class="btn btn-danger" id="__confirm-ok">Confirm</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  document.getElementById("__confirm-ok").onclick = () => {
    overlay.remove();
    onConfirm();
  };
}

/* ── Guard: redirect if not logged in ────────── */
function requireAuth() {
  if (!Auth.isLoggedIn()) {
    window.location.href = "/index.html";
    return false;
  }
  return true;
}

function renderComments(comments) {
  const box = document.getElementById("comments-container");

  if (!comments || comments.length === 0) {
    box.innerHTML = "<p>No comments yet</p>";
    return;
  }

  box.innerHTML = comments.map(c => `
    <div class="comment-item">
      <div class="comment-avatar">${initials(c.user_name)}</div>
      <div class="comment-content">
        <div class="comment-meta">
          <span class="comment-user">${c.user_name}</span>
          <span class="comment-date">${fmtDate(c.created_at)}</span>
        </div>

        <div class="comment-text" id="c-text-${c.id}">
          ${c.comment}
        </div>

        ${c.is_own ? `
          <div class="comment-actions">
            <button onclick="editComment(${c.id})">Edit</button>
            <button onclick="deleteComment(${c.id})">Delete</button>
          </div>
        ` : ""}
      </div>
    </div>
  `).join("");
}
