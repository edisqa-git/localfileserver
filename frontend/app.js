const state = {
  username: "",
  password: "",
  role: "",
  createdAt: "",
  previewUrls: new Map(),
};

const el = {
  topActions: document.getElementById("top-actions"),
  landingPanel: document.getElementById("landing-panel"),
  authPanel: document.getElementById("auth-panel"),
  appPanel: document.getElementById("app-panel"),
  goLoginBtn: document.getElementById("go-login-btn"),
  goSignupBtn: document.getElementById("go-signup-btn"),
  loginForm: document.getElementById("login-form"),
  loginUsername: document.getElementById("login-username"),
  loginPassword: document.getElementById("login-password"),
  signupForm: document.getElementById("signup-form"),
  signupUsername: document.getElementById("signup-username"),
  signupPassword: document.getElementById("signup-password"),
  uploadForm: document.getElementById("upload-form"),
  uploadFile: document.getElementById("upload-file"),
  dropZone: document.getElementById("drop-zone"),
  refreshBtn: document.getElementById("refresh-btn"),
  logoutBtn: document.getElementById("logout-btn"),
  authStatus: document.getElementById("auth-status"),
  fileStatus: document.getElementById("file-status"),
  fileList: document.getElementById("file-list"),
};

function setStatus(target, msg, isError = false) {
  target.textContent = msg;
  target.style.color = isError ? "#9b2226" : "#5d5449";
}

function authHeader() {
  if (!state.username || !state.password) {
    return {};
  }
  const token = btoa(`${state.username}:${state.password}`);
  return { Authorization: `Basic ${token}` };
}

function showLandingOnly() {
  el.landingPanel.hidden = false;
  el.authPanel.hidden = true;
  el.appPanel.hidden = true;
  el.topActions.hidden = true;
}

function showAuthPanel(mode = "login") {
  el.landingPanel.hidden = false;
  el.authPanel.hidden = false;
  el.appPanel.hidden = true;
  el.topActions.hidden = true;
  if (mode === "signup") {
    el.signupUsername.focus();
  } else {
    el.loginUsername.focus();
  }
}

function showAppPanel() {
  el.landingPanel.hidden = true;
  el.authPanel.hidden = true;
  el.appPanel.hidden = false;
  el.topActions.hidden = false;
}

function logout(message = "Logged out.") {
  state.username = "";
  state.password = "";
  state.role = "";
  state.createdAt = "";
  clearPreviewUrls();
  el.loginForm.reset();
  el.signupForm.reset();
  el.uploadForm.reset();
  el.fileList.innerHTML = "";
  setStatus(el.authStatus, message);
  setStatus(el.fileStatus, "");
  showLandingOnly();
}

function enforceFreshLogin() {
  logout("");
  if (el.loginUsername) el.loginUsername.value = "";
  if (el.loginPassword) el.loginPassword.value = "";
}

function bytesToSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

async function fetchFiles() {
  if (!state.username || !state.password) {
    setStatus(el.fileStatus, "Login first to load files.", true);
    return;
  }

  const resp = await fetch("/api/files", {
    headers: {
      ...authHeader(),
      Accept: "application/json",
    },
  });
  if (!resp.ok) {
    throw new Error(`Failed to load files (${resp.status})`);
  }
  const data = await resp.json();
  renderFiles(data.files || []);
}

function clearPreviewUrls() {
  for (const url of state.previewUrls.values()) {
    URL.revokeObjectURL(url);
  }
  state.previewUrls.clear();
}

async function loadImagePreview(fileName, imgEl) {
  try {
    const resp = await fetch(`/file/${encodeURIComponent(fileName)}`, {
      headers: authHeader(),
    });
    if (!resp.ok) return;
    const blob = await resp.blob();
    if (!blob.type.startsWith("image/")) return;

    const old = state.previewUrls.get(fileName);
    if (old) URL.revokeObjectURL(old);

    const url = URL.createObjectURL(blob);
    state.previewUrls.set(fileName, url);
    imgEl.src = url;
    imgEl.alt = fileName;
    imgEl.classList.add("image");
    imgEl.textContent = "";
  } catch (_error) {
    // Ignore preview load errors and keep fallback state.
  }
}

function renderFiles(files) {
  clearPreviewUrls();
  el.fileList.innerHTML = "";
  if (!files.length) {
    el.fileList.textContent = "No files yet.";
    return;
  }

  for (const file of files) {
    const row = document.createElement("div");
    row.className = "file-item";

    const meta = document.createElement("div");
    meta.className = "file-meta";

    const preview = file.is_image ? document.createElement("img") : document.createElement("div");
    preview.className = "preview";
    preview.textContent = file.is_image ? "Loading" : "File";
    meta.appendChild(preview);

    const textWrap = document.createElement("div");
    textWrap.className = "meta-text";

    const name = document.createElement("div");
    name.className = "file-name";
    name.textContent = file.name;
    textWrap.appendChild(name);

    const size = document.createElement("div");
    size.className = "file-size";
    size.textContent = bytesToSize(file.size);
    textWrap.appendChild(size);
    meta.appendChild(textWrap);

    const actions = document.createElement("div");
    actions.className = "file-actions";

    const downloadBtn = document.createElement("button");
    downloadBtn.type = "button";
    downloadBtn.setAttribute("data-download", file.name);
    downloadBtn.textContent = "Download";
    actions.appendChild(downloadBtn);

    const deleteBtn = document.createElement("button");
    deleteBtn.type = "button";
    deleteBtn.className = "delete";
    deleteBtn.setAttribute("data-delete", file.name);
    deleteBtn.textContent = "Delete";
    actions.appendChild(deleteBtn);

    row.appendChild(meta);
    row.appendChild(actions);
    el.fileList.appendChild(row);

    if (file.is_image) {
      loadImagePreview(file.name, preview);
    }
  }
}

async function signup(username, password) {
  const resp = await fetch("/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!resp.ok) {
    const msg = await resp.text();
    throw new Error(`Signup failed (${resp.status}): ${msg}`);
  }
  return resp.json();
}

async function login(username, password) {
  state.username = String(username || "").trim();
  state.password = String(password || "");

  if (!state.username || !state.password) {
    throw new Error("Username and password are required.");
  }

  const resp = await fetch("/whoami", { headers: authHeader() });
  if (!resp.ok) {
    throw new Error(`Login failed (${resp.status})`);
  }

  const me = await resp.json();
  state.role = String(me.role || "");
  state.createdAt = String(me.created_at || "");
  const roleLabel = state.role ? ` (${state.role})` : "";
  setStatus(el.authStatus, `Logged in as ${state.username}${roleLabel}`);
  setStatus(el.fileStatus, "Loading files...");
  await fetchFiles();
  showAppPanel();
  setStatus(el.fileStatus, "Files loaded.");
}

async function uploadFile(file) {
  const formData = new FormData();
  formData.append("file", file);

  const resp = await fetch("/upload", {
    method: "POST",
    headers: authHeader(),
    body: formData,
  });
  if (!resp.ok) {
    throw new Error(`Upload failed (${resp.status})`);
  }
}

async function uploadFiles(files) {
  for (const file of files) {
    await uploadFile(file);
  }
}

async function deleteFile(name) {
  const resp = await fetch(`/file/${encodeURIComponent(name)}`, {
    method: "DELETE",
    headers: authHeader(),
  });
  if (!resp.ok) {
    throw new Error(`Delete failed (${resp.status})`);
  }
}

async function downloadFile(name) {
  const resp = await fetch(`/download/${encodeURIComponent(name)}`, {
    headers: authHeader(),
  });
  if (!resp.ok) {
    throw new Error(`Download failed (${resp.status})`);
  }
  const blob = await resp.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

el.loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const fd = new FormData(el.loginForm);
  const username = String(fd.get("username") || "").trim();
  const password = String(fd.get("password") || "");

  if (!username || !password) {
    setStatus(el.authStatus, "Username and password are required.", true);
    return;
  }

  try {
    await login(username, password);
  } catch (error) {
    setStatus(el.authStatus, error.message, true);
  }
});

el.goLoginBtn.addEventListener("click", () => {
  showAuthPanel("login");
  setStatus(el.authStatus, "Enter your username and password to continue.");
});

el.goSignupBtn.addEventListener("click", () => {
  showAuthPanel("signup");
  setStatus(el.authStatus, "Create a new account to start with your own directory.");
});

el.signupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const fd = new FormData(el.signupForm);
  const username = String(fd.get("username") || "").trim();
  const password = String(fd.get("password") || "");

  try {
    await signup(username, password);
    await login(username, password);
    setStatus(el.fileStatus, `Signup successful. Logged in as ${username}.`);
  } catch (error) {
    setStatus(el.authStatus, error.message, true);
  }
});

el.uploadForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = el.uploadFile.files && el.uploadFile.files[0];
  if (!file) {
    setStatus(el.fileStatus, "Select a file first.", true);
    return;
  }
  try {
    await uploadFile(file);
    setStatus(el.fileStatus, `Uploaded ${file.name}`);
    el.uploadForm.reset();
    await fetchFiles();
  } catch (error) {
    setStatus(el.fileStatus, error.message, true);
  }
});

["dragenter", "dragover"].forEach((name) => {
  el.dropZone.addEventListener(name, (event) => {
    event.preventDefault();
    el.dropZone.classList.add("dragging");
  });
});

["dragleave", "dragend", "drop"].forEach((name) => {
  el.dropZone.addEventListener(name, (event) => {
    event.preventDefault();
    el.dropZone.classList.remove("dragging");
  });
});

el.dropZone.addEventListener("drop", async (event) => {
  const files = event.dataTransfer && event.dataTransfer.files
    ? Array.from(event.dataTransfer.files)
    : [];
  if (!files.length) return;

  if (!state.username || !state.password) {
    setStatus(el.fileStatus, "Login first to upload files.", true);
    return;
  }

  try {
    setStatus(el.fileStatus, `Uploading ${files.length} file(s)...`);
    await uploadFiles(files);
    setStatus(el.fileStatus, `Uploaded ${files.length} file(s).`);
    await fetchFiles();
  } catch (error) {
    setStatus(el.fileStatus, error.message, true);
  }
});

el.refreshBtn.addEventListener("click", async () => {
  try {
    await fetchFiles();
    setStatus(el.fileStatus, "Refreshed.");
  } catch (error) {
    setStatus(el.fileStatus, error.message, true);
  }
});

el.logoutBtn.addEventListener("click", () => {
  logout("Logged out.");
});

el.fileList.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;

  const toDownload = target.getAttribute("data-download");
  const toDelete = target.getAttribute("data-delete");

  try {
    if (toDownload) {
      await downloadFile(toDownload);
      setStatus(el.fileStatus, `Downloaded ${toDownload}`);
    }
    if (toDelete) {
      await deleteFile(toDelete);
      setStatus(el.fileStatus, `Deleted ${toDelete}`);
      await fetchFiles();
    }
  } catch (error) {
    setStatus(el.fileStatus, error.message, true);
  }
});

window.addEventListener("DOMContentLoaded", () => {
  enforceFreshLogin();
});

window.addEventListener("pageshow", (event) => {
  if (event.persisted) {
    enforceFreshLogin();
  }
});

enforceFreshLogin();
