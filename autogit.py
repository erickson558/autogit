# -*- coding: utf-8 -*-
"""
Git Helper GUI – v0.2.6
- FIX: Autenticación PAT mejorada con URL correcta y manejo de errores
- FIX: Eliminación de prompts interactivos en comandos git
- FIX: Configuración robusta de credenciales HTTPS
- ADD: Verificación mejorada de PAT antes del push
- ADD: Manejo específico de errores de autenticación GitHub
"""

import os, sys, json, hashlib, threading, datetime, queue, traceback, subprocess, time
import base64
import urllib.request
import urllib.error
import json as json_lib

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except Exception as e:
    print("Tkinter no disponible:", e); sys.exit(1)

APP_NAME = "Git Helper GUI"
INITIAL_VERSION = "0.0.1"

def app_dir():
    return os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))

CONFIG_PATH = os.path.join(app_dir(), "config_autogit.json")
LOG_PATH    = os.path.join(app_dir(), "log_autogit.txt")

# ---------- Utilidades ----------
def log_line(msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {msg}\n")

def safe_read_json(path, default):
    try:
        if not os.path.exists(path): return default
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        log_line(f"ERROR leyendo JSON: {e}"); return default

def safe_write_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

def file_hash(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""): h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        log_line(f"ERROR hash código: {e}"); return ""

def bump_version(v):
    try:
        a,b,c = (list(map(int,(v.split(".")+["0","0","0"])[:3])))
        c += 1
        return f"{a}.{b}.{c}"
    except: return INITIAL_VERSION

# ---------- Fix mojibake ----------
def _unmojibake_if_needed(s):
    """Corrige mojibake típico (UTF-8 leído como latin1)."""
    try:
        fixed = s.encode("latin1").decode("utf-8")
        if ("Ã" in s or "�" in s) and any(ch in fixed for ch in u"áéíóúñÁÉÍÓÚÑ"):
            return fixed
    except Exception:
        pass
    return s

# ---------- Config ----------
DEFAULT_CONFIG = {
    "version": INITIAL_VERSION,
    "last_code_hash": "",
    "window_geometry": "1040x720+100+100",
    "autostart": True,
    "autoclose_enabled": False,
    "autoclose_seconds": 60,
    "status_text": "Listo.",
    "shortcuts_enabled": True,

    # Proyecto / repo
    "project_path": app_dir(),
    "repo_name": "",
    "follow_exe_folder": True,

    # Git identity
    "git_user_name": "erickson558",
    "git_user_email": "erickson558@hotmail.com",

    # Autenticación: "gh" | "https_pat" | "ssh"
    "auth_method": "https_pat",
    "github_user": "erickson558",

    # HTTPS + PAT (OBLIGATORIO)
    "pat_username": "erickson558",
    "pat_token": "",
    "pat_save_in_credential_manager": True,

    # SSH
    "ssh_key_path": "",

    # Commit / flujo
    "commit_message": "Actualización automática",
    "create_readme_if_missing": True,

    # Grandes / limpieza historia
    "max_file_size_mb": 95,
    "history_purge_patterns": ["autogit.exe", "autogit*.exe"],
    "force_push_after_purge": True
}

# .gitignore base
GITIGNORE_LINES = [
    "# --- GitHelper default ---",
    "config.json",
    "log.txt",
    "config_autogit.json",
    "log_autogit.txt",
    "*.exe",
    "*.pyc",
    "__pycache__/",
    ".venv/",
    "venv/",
    "node_modules/",
    ".DS_Store",
    "Thumbs.db",
]

class AboutDialog(tk.Toplevel):
    def __init__(self, master, version):
        super().__init__(master)
        self.title("Acerca de"); self.resizable(False, False)
        self.geometry("+{}+{}".format(master.winfo_rootx()+80, master.winfo_rooty()+80))
        self.configure(bg="#101418")
        frm = tk.Frame(self, bg="#101418"); frm.pack(padx=16, pady=16)
        tk.Label(
            frm,
            text=f"{APP_NAME}\n\n{version} creado por Synyster Rick, {datetime.datetime.now().year} Derechos Reservados",
            fg="#E6EDF3", bg="#101418", font=("Segoe UI", 10)
        ).pack(pady=(0,12))
        ttk.Button(frm, text="Cerrar (Esc)", command=self.destroy).pack()
        self.bind("<Escape>", lambda e: self.destroy())

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME); self.configure(bg="#0B0F14")
        self.cfg = safe_read_json(CONFIG_PATH, DEFAULT_CONFIG.copy())

        # Bump versión si cambió el binario/script
        code_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
        h = file_hash(code_path)
        if h and h != self.cfg.get("last_code_hash",""):
            self.cfg["version"] = bump_version(self.cfg.get("version", INITIAL_VERSION))
            self.cfg["last_code_hash"] = h
            safe_write_json(CONFIG_PATH, self.cfg)
            log_line(f"Version bump por cambio de código: {self.cfg['version']}")

        self._build_style(); self._build_menu(); self._build_widgets()

        # Forzar usar SIEMPRE la carpeta del ejecutable como project_path
        if self.cfg.get("follow_exe_folder", True):
            exe_dir = app_dir()
            self.project_path_var.set(exe_dir)
            self._on_project_path_change()
            self._autodetect_repo_name()

        try:
            self.geometry(self.cfg.get("window_geometry") or DEFAULT_CONFIG["window_geometry"])
        except:
            self.geometry(DEFAULT_CONFIG["window_geometry"])

        self.worker_thread = None
        self.worker_queue  = queue.Queue()
        self.running = False
        self.countdown_job = None
        self.autoclose_remaining = 0

        if self.cfg.get("shortcuts_enabled", True): self._bind_shortcuts()
        self.after(100, self._poll_worker_queue)

        if self.cfg.get("autoclose_enabled", False): self._schedule_autoclose()
        if self.cfg.get("autostart", True): self.after(300, self._start_pipeline)

        log_line(f"App iniciada v{self.cfg['version']}")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # ---------- UI ----------
    def _build_style(self):
        st = ttk.Style(self)
        for theme in ("vista","clam"):
            try: st.theme_use(theme); break
            except: pass
        st.configure("TFrame", background="#0B0F14")
        st.configure("TLabel", background="#0B0F14", foreground="#E6EDF3", font=("Segoe UI", 10))
        st.configure("TButton", padding=6)
        st.configure("TCheckbutton", background="#0B0F14", foreground="#E6EDF3", font=("Segoe UI", 10))
        st.configure("Status.TLabel", background="#0A0E12", foreground="#9FB4C7", font=("Segoe UI", 9))

    def _build_menu(self):
        menubar = tk.Menu(self, tearoff=0); self.config(menu=menubar)
    
        m_app = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Aplicación", menu=m_app, underline=0)
        m_app.add_command(label="Ejecutar pipeline", accelerator="Ctrl+R", command=self._start_pipeline)
        m_app.add_command(label="Test PAT Token", accelerator="Ctrl+T", command=self._test_pat_token)
        m_app.add_command(label="Detener", accelerator="Ctrl+D", command=self._stop_pipeline)
        m_app.add_separator()
        m_app.add_command(label="Salir", accelerator="Ctrl+Q", command=self.on_close)
    
        m_help = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Ayuda", menu=m_help, underline=0)
        m_help.add_command(label="About", accelerator="F1", command=self._show_about)
        m_help.add_command(label="Instrucciones PAT", accelerator="F2", command=self._show_pat_instructions)

    def _build_widgets(self):
        top = ttk.Frame(self); top.pack(fill="x", padx=16, pady=12)
        ttk.Label(top, text=APP_NAME, font=("Segoe UI Semibold", 14)).pack(side="left")
        self.version_label = ttk.Label(top, text=f"Versión: {self.cfg.get('version', INITIAL_VERSION)}",
                                       font=("Segoe UI Semibold", 10)); self.version_label.pack(side="right")

        body = ttk.Frame(self); body.pack(fill="both", expand=True, padx=16, pady=8)

        rowA = ttk.Frame(body); rowA.pack(fill="x", pady=(2,2))
        self.autostart_var = tk.BooleanVar(value=self.cfg.get("autostart", True))
        ttk.Checkbutton(rowA, text="Autoiniciar pipeline al abrir",
                        variable=self.autostart_var,
                        command=lambda: self._on_bool_change("autostart", self.autostart_var.get())
                        ).pack(side="left")
        self.autoclose_var = tk.BooleanVar(value=self.cfg.get("autoclose_enabled", False))
        ttk.Checkbutton(rowA, text="Autocerrar después de (seg):",
                        variable=self.autoclose_var,
                        command=lambda: self._on_bool_change("autoclose_enabled", self.autoclose_var.get())
                        ).pack(side="left", padx=(20,6))
        self.autoclose_secs_var = tk.StringVar(value=str(self.cfg.get("autoclose_seconds", 60)))
        e_secs = ttk.Entry(rowA, width=6, textvariable=self.autoclose_secs_var)
        e_secs.pack(side="left"); e_secs.bind("<FocusOut>", lambda e: self._on_int_change("autoclose_seconds", self.autoclose_secs_var.get()))
        e_secs.bind("<Return>",   lambda e: self._on_int_change("autoclose_seconds", self.autoclose_secs_var.get()))

        rowB = ttk.Frame(body); rowB.pack(fill="x", pady=(8,4))
        ttk.Label(rowB, text="Ruta del proyecto:").pack(side="left")
        self.project_path_var = tk.StringVar(value=self.cfg.get("project_path", app_dir()))
        e_path = ttk.Entry(rowB, width=64, textvariable=self.project_path_var,
                           state="readonly" if self.cfg.get("follow_exe_folder", True) else "normal")
        e_path.pack(side="left", padx=6, fill="x", expand=True)
        e_path.bind("<FocusOut>", lambda e: self._on_project_path_change())
        e_path.bind("<Return>",   lambda e: self._on_project_path_change())
        ttk.Button(rowB, text="Examinar…",
                   command=self._browse_folder,
                   state="disabled" if self.cfg.get("follow_exe_folder", True) else "normal").pack(side="left", padx=(6,0))

        rowC = ttk.Frame(body); rowC.pack(fill="x", pady=(4,4))
        ttk.Label(rowC, text="Nombre del repo (GitHub):").pack(side="left")
        self.repo_name_var = tk.StringVar(value=self.cfg.get("repo_name",""))
        e_repo = ttk.Entry(rowC, width=40, textvariable=self.repo_name_var)
        e_repo.pack(side="left", padx=6)
        e_repo.bind("<FocusOut>", lambda e: self._on_str_change("repo_name", self.repo_name_var.get()))
        e_repo.bind("<Return>",   lambda e: self._on_str_change("repo_name", self.repo_name_var.get()))
        ttk.Button(rowC, text="Autodetectar", command=self._autodetect_repo_name).pack(side="left", padx=(6,0))

        rowD = ttk.Frame(body); rowD.pack(fill="x", pady=(8,4))
        ttk.Label(rowD, text="Git user.name:").pack(side="left")
        self.git_user_name_var = tk.StringVar(value=self.cfg.get("git_user_name",""))
        e_un = ttk.Entry(rowD, width=24, textvariable=self.git_user_name_var)
        e_un.pack(side="left", padx=6)
        e_un.bind("<FocusOut>", lambda e: self._on_str_change("git_user_name", self.git_user_name_var.get()))
        e_un.bind("<Return>",   lambda e: self._on_str_change("git_user_name", self.git_user_name_var.get()))
        ttk.Label(rowD, text="Git user.email:").pack(side="left", padx=(16,0))
        self.git_user_email_var = tk.StringVar(value=self.cfg.get("git_user_email",""))
        e_ue = ttk.Entry(rowD, width=28, textvariable=self.git_user_email_var)
        e_ue.pack(side="left", padx=6)
        e_ue.bind("<FocusOut>", lambda e: self._on_str_change("git_user_email", self.git_user_email_var.get()))
        e_ue.bind("<Return>",   lambda e: self._on_str_change("git_user_email", self.git_user_email_var.get()))

        rowE = ttk.LabelFrame(body, text="Autenticación GitHub (OBLIGATORIO)"); rowE.pack(fill="x", pady=(10,6))
        ttk.Label(rowE, text="Método:").grid(row=0, column=0, sticky="w", padx=6, pady=6)
        self.auth_method_var = tk.StringVar(value=self.cfg.get("auth_method","https_pat"))
        cb_auth = ttk.Combobox(rowE, textvariable=self.auth_method_var, state="readonly",
                               values=["https_pat","ssh","gh"], width=12)
        cb_auth.grid(row=0, column=1, sticky="w", padx=6, pady=6)
        cb_auth.bind("<<ComboboxSelected>>", lambda e: self._on_auth_method_change())
        ttk.Label(rowE, text="Usuario GitHub:").grid(row=0, column=2, sticky="w", padx=(16,6))
        self.github_user_var = tk.StringVar(value=self.cfg.get("github_user",""))
        e_ghu = ttk.Entry(rowE, width=22, textvariable=self.github_user_var)
        e_ghu.grid(row=0, column=3, sticky="w", padx=6, pady=6)
        e_ghu.bind("<FocusOut>", lambda e: self._on_str_change("github_user", self.github_user_var.get()))
        e_ghu.bind("<Return>",   lambda e: self._on_str_change("github_user", self.github_user_var.get()))

        # PAT Token section - INLINE TEST + STATUS
        pat_frame = ttk.Frame(rowE); pat_frame.grid(row=1, column=0, columnspan=5, sticky="we", padx=6, pady=6)
        ttk.Label(pat_frame, text="🔑 PAT Token (OBLIGATORIO):", foreground="#FF6B6B").pack(side="left")
        self.pat_token_var = tk.StringVar(value=self.cfg.get("pat_token",""))
        self.e_pt = ttk.Entry(pat_frame, width=40, textvariable=self.pat_token_var, show="•")
        self.e_pt.pack(side="left", padx=6, fill="x", expand=True)
        self.e_pt.bind("<KeyRelease>", lambda e: self._on_str_change("pat_token", self.pat_token_var.get()))

        self._pat_shown = False
        def toggle_pat():
            self._pat_shown = not self._pat_shown
            self.e_pt.config(show="" if self._pat_shown else "•")
        ttk.Button(pat_frame, text="Mostrar", width=8, command=toggle_pat).pack(side="left", padx=6)

        ttk.Button(pat_frame, text="Test PAT", width=8, command=self._test_pat_token).pack(side="left", padx=6)
        self.pat_status_var = tk.StringVar(value="")
        ttk.Label(pat_frame, textvariable=self.pat_status_var).pack(side="left", padx=(8,0))

        ttk.Button(pat_frame, text="Instrucciones", width=10, command=self._show_pat_instructions).pack(side="left", padx=6)

        ttk.Label(rowE, text="PAT usuario:").grid(row=2, column=0, sticky="w", padx=6, pady=6)
        self.pat_user_var = tk.StringVar(value=self.cfg.get("pat_username","erickson558"))
        e_pu = ttk.Entry(rowE, width=20, textvariable=self.pat_user_var)
        e_pu.grid(row=2, column=1, sticky="w", padx=6, pady=6)
        e_pu.bind("<FocusOut>", lambda e: self._on_str_change("pat_username", self.pat_user_var.get()))
        e_pu.bind("<Return>",   lambda e: self._on_str_change("pat_username", self.pat_user_var.get()))

        self.pat_save_var = tk.BooleanVar(value=self.cfg.get("pat_save_in_credential_manager", True))
        ttk.Checkbutton(rowE, text="Guardar token en Credential Manager (Windows)",
                        variable=self.pat_save_var,
                        command=lambda: self._on_bool_change("pat_save_in_credential_manager", self.pat_save_var.get())
                        ).grid(row=2, column=2, columnspan=3, sticky="w", padx=6, pady=4)

        ttk.Label(rowE, text="Clave SSH (opcional):").grid(row=3, column=0, sticky="w", padx=6, pady=6)
        self.ssh_key_var = tk.StringVar(value=self.cfg.get("ssh_key_path",""))
        e_sk = ttk.Entry(rowE, width=40, textvariable=self.ssh_key_var)
        e_sk.grid(row=3, column=1, columnspan=2, sticky="we", padx=6, pady=6)
        e_sk.bind("<FocusOut>", lambda e: self._on_str_change("ssh_key_path", self.ssh_key_var.get()))
        e_sk.bind("<Return>",   lambda e: self._on_str_change("ssh_key_path", self.ssh_key_var.get()))
        ttk.Button(rowE, text="Examinar…", command=self._browse_ssh_key).grid(row=3, column=3, sticky="w", padx=6)

        for i in range(5): rowE.grid_columnconfigure(i, weight=1)

        rowF = ttk.Frame(body); rowF.pack(fill="x", pady=(8,4))
        ttk.Label(rowF, text="Mensaje de commit:").pack(side="left")
        self.commit_message_var = tk.StringVar(value=self.cfg.get("commit_message","Actualización automática"))
        e_msg = ttk.Entry(rowF, width=64, textvariable=self.commit_message_var)
        e_msg.pack(side="left", padx=6, fill="x", expand=True)
        e_msg.bind("<KeyRelease>", lambda e: self._on_str_change("commit_message", self.commit_message_var.get()))
        self.create_readme_var = tk.BooleanVar(value=self.cfg.get("create_readme_if_missing", True))
        ttk.Checkbutton(rowF, text="Crear README.md si falta",
                        variable=self.create_readme_var,
                        command=lambda: self._on_bool_change("create_readme_if_missing", self.create_readme_var.get())
                        ).pack(side="left", padx=(10,0))

        rowG = ttk.Frame(body); rowG.pack(fill="x", pady=(12,6))
        self.btn_run  = ttk.Button(rowG, text="Ejecutar pipeline (Ctrl+R)", command=self._start_pipeline)
        self.btn_test = ttk.Button(rowG, text="Test PAT Token (Ctrl+T)", command=self._test_pat_token)
        self.btn_stop = ttk.Button(rowG, text="Detener (Ctrl+D)", command=self._stop_pipeline, state="disabled")
        self.btn_exit = ttk.Button(rowG, text="Salir (Ctrl+Q)", command=self.on_close)
        self.btn_run.pack(side="left"); self.btn_test.pack(side="left", padx=8)
        self.btn_stop.pack(side="left", padx=8); self.btn_exit.pack(side="right")

        logf = ttk.Frame(body); logf.pack(fill="both", expand=True, pady=(8,8))
        self.txt_log = tk.Text(logf, height=14, bg="#0F1620", fg="#C9D1D9", insertbackground="#C9D1D9", relief="flat", wrap="word")
        self.txt_log.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(logf, orient="vertical", command=self.txt_log.yview); sb.pack(side="right", fill="y")
        self.txt_log.configure(yscrollcommand=sb.set)

        status = tk.Frame(self, bg="#0A0E12", bd=1, relief="sunken", height=24)
        status.pack(side="bottom", fill="x"); status.pack_propagate(False)
        self.status_var = tk.StringVar(value=self.cfg.get("status_text","Listo."))
        ttk.Label(status, textvariable=self.status_var, style="Status.TLabel").pack(side="left", padx=10)
        self.countdown_var = tk.StringVar(value="")
        ttk.Label(status, textvariable=self.countdown_var, style="Status.TLabel").pack(side="right", padx=10)

    def _on_auth_method_change(self):
        method = self.auth_method_var.get()
        self._on_str_change("auth_method", method)
        if method == "https_pat":
            self._status("Método: HTTPS con PAT Token (Recomendado)")
        elif method == "ssh":
            self._status("Método: SSH con clave privada")
        elif method == "gh":
            self._status("Método: GitHub CLI")

    def _show_pat_instructions(self):
        instructions = """🔑 CREAR PERSONAL ACCESS TOKEN (PAT) EN GITHUB:

1. Ve a: https://github.com/settings/tokens
2. Haz clic en "Generate new token" → "Generate new token (classic)"
3. Pon un nombre descriptivo (ej: "AutoGit App")
4. Selecciona estos permisos:
   - ✅ repo (todo)
   - ✅ workflow
   - ✅ write:packages
   - ✅ delete:packages
5. Expiración: 90 días (recomendado)
6. Haz clic en "Generate token"
7. COPIA el token inmediatamente (solo se muestra una vez)
8. Pega el token en el campo "PAT Token" de esta aplicación

⚠️ IMPORTANTE: El token es como una contraseña, guárdalo de forma segura."""
        messagebox.showinfo("Instrucciones PAT Token", instructions)

    # ---------- Test PAT Token (MEJORADO) ----------
    def _test_pat_token(self, *_):
        """
        Test PAT mejorado con verificación específica de autenticación Git
        """
        pat_token = self.pat_token_var.get().strip()
        github_user = self.github_user_var.get().strip()

        if not pat_token:
            self._append_log("❌ ERROR: No hay PAT token configurado")
            try: 
                self.pat_status_var.set("❌ Sin token")
            except: 
                pass
            return

        if not github_user:
            self._append_log("❌ ERROR: No hay usuario GitHub configurado")
            try: 
                self.pat_status_var.set("❌ Sin usuario")
            except: 
                pass
            return

        if getattr(self, "_pat_testing", False):
            self._append_log("ℹ️ Test PAT ya está en ejecución…")
            return

        self._pat_testing = True
        try:
            try: 
                self.pat_status_var.set("⏳ Probando PAT…")
            except: 
                pass

            def worker():
                ok = self._test_pat_token_impl(self._append_log)
                def ui_update():
                    try:
                        self.pat_status_var.set("✅ Válido" if ok else "❌ Inválido")
                    except:
                        pass
                self.after(0, ui_update)
                self._pat_testing = False

            threading.Thread(target=worker, daemon=True).start()
        except Exception as e:
            self._append_log(f"ERROR lanzando test PAT: {e}")
            try: 
                self.pat_status_var.set("❌ Error")
            except: 
                pass
            self._pat_testing = False

    def _test_pat_token_impl(self, callback):
        """Lógica mejorada de test de PAT con enfoque en autenticación Git"""
        pat_token  = self.pat_token_var.get().strip()
        github_user = self.github_user_var.get().strip()
        repo_name   = self.repo_name_var.get().strip()

        callback("".ljust(60, "="))
        callback("🔐 Iniciando test COMPLETO de PAT token…")
        callback(f"Usuario: {github_user}")
        callback(f"Token: {pat_token[:8]}...")

        # Test 1: API GitHub básica
        callback("1) Verificando autenticación básica a GitHub API…")
        try:
            url = "https://api.github.com/user"
            headers = {
                'Authorization': f'token {pat_token}',
                'User-Agent': 'AutoGit-App',
                'Accept': 'application/vnd.github.v3+json'
            }
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json_lib.loads(response.read().decode())
                callback("   ✅ Autenticación API exitosa")
                callback(f"   👤 login: {data.get('login', 'N/A')}")
        except urllib.error.HTTPError as e:
            if e.code == 401:
                callback("   ❌ Token inválido o expirado")
                return False
            else:
                callback(f"   ❌ Error HTTP {e.code}")
                return False
        except Exception as e:
            callback(f"   ❌ Error de conexión: {str(e)}")
            return False

        # Test 2: Autenticación Git específica (CRÍTICO para el error)
        callback("2) Verificando autenticación Git (método crítico)…")
        test_success = self._test_git_authentication(github_user, pat_token, repo_name, callback)
        
        if test_success:
            callback("🎉 TEST COMPLETO: PAT configurado correctamente para operaciones Git")
            return True
        else:
            callback("❌ TEST FALLIDO: El PAT no funciona para operaciones Git")
            return False

    def _test_git_authentication(self, github_user, pat_token, repo_name, callback):
        """Test específico de autenticación Git que replica las condiciones del push"""
        test_dir = os.path.join(os.path.expanduser("~"), ".autogit_test")
        
        try:
            # Crear directorio temporal
            os.makedirs(test_dir, exist_ok=True)
            
            # Configuración Git mínima sin prompts
            env = os.environ.copy()
            env.update({
                'GIT_TERMINAL_PROMPT': '0',
                'GCM_INTERACTIVE': 'Never',
                'GIT_ASKPASS': 'echo',
                'GIT_USERNAME': github_user,
                'GIT_PASSWORD': pat_token
            })
            
            # Inicializar repo test
            if not os.path.exists(os.path.join(test_dir, ".git")):
                rc, out = self._popen_capture_any(["git", "init"], cwd=test_dir, env=env)
                if rc != 0:
                    callback("   ❌ Error inicializando repo test")
                    return False

            # Configurar usuario
            self._popen_run_any(["git", "config", "user.name", "Test User"], cwd=test_dir, env=env)
            self._popen_run_any(["git", "config", "user.email", "test@example.com"], cwd=test_dir, env=env)
            
            # Configurar origin con formato CORRECTO para PAT
            test_repo = repo_name or "autogit-test-repo"
            origin_url = f"https://{github_user}:{pat_token}@github.com/{github_user}/{test_repo}.git"
            
            # Remover origin existente
            self._popen_run_any(["git", "remote", "remove", "origin"], cwd=test_dir, env=env)
            
            # Agregar origin
            rc, out = self._popen_capture_any(["git", "remote", "add", "origin", origin_url], 
                                            cwd=test_dir, env=env)
            if rc != 0:
                callback(f"   ❌ Error configurando origin: {out}")
                return False

            # Test crítico: ls-remote con timeout corto
            callback("   🔍 Probando conexión Git con origin…")
            rc, out = self._popen_capture_any(["git", "ls-remote", "origin"], 
                                            cwd=test_dir, env=env, timeout=15)
            
            if rc == 0:
                callback("   ✅ Autenticación Git exitosa")
                return True
            else:
                # Análisis detallado del error
                error_msg = out.lower() if out else ""
                callback(f"   ❌ Error Git: {out.strip()}")
                
                if "authentication failed" in error_msg:
                    callback("   💡 El PAT es inválido o no tiene permisos 'repo'")
                elif "could not read from remote repository" in error_msg:
                    callback("   💡 El repositorio no existe o no hay acceso")
                elif "timed out" in error_msg:
                    callback("   💡 Timeout de red, pero el PAT podría ser válido")
                else:
                    callback("   💡 Error desconocido de autenticación Git")
                
                return False
                
        except subprocess.TimeoutExpired:
            callback("   ⚠️ Timeout en test Git (puede ser normal en redes restrictivas)")
            return False
        except Exception as e:
            callback(f"   ❌ Excepción en test Git: {str(e)}")
            return False
        finally:
            # Limpieza
            try:
                import shutil
                shutil.rmtree(test_dir, ignore_errors=True)
            except:
                pass

    # ---------- Configuración de autenticación MEJORADA ----------
    def _setup_credentials(self, project_path, method):
        """Configuración robusta de credenciales para HTTPS+PAT"""
        if method == "https_pat":
            pat_token = self.pat_token_var.get().strip()
            github_user = self.github_user_var.get().strip()
            repo_name = self.repo_name_var.get().strip()
            
            if not pat_token:
                self.worker_queue.put(("log", "❌ ERROR: No hay PAT token configurado"))
                return False
            
            if not github_user or not repo_name:
                self.worker_queue.put(("log", "❌ ERROR: Faltan usuario GitHub o nombre de repo"))
                return False

            # Verificación rápida del PAT antes de continuar
            if not self._test_pat_token_quick():
                self.worker_queue.put(("log", "❌ El PAT token no es válido (verificación rápida falló)"))
                return False

            # Configurar URL de origin con formato CORRECTO
            origin_url = f"https://{github_user}:{pat_token}@github.com/{github_user}/{repo_name}.git"
            
            self.worker_queue.put(("log", "🔐 Configurando autenticación HTTPS con PAT…"))
            
            # Configuración Git para deshabilitar prompts
            config_steps = [
                (["git", "config", "credential.helper", "store"], "credential.helper"),
                (["git", "config", "credential.https://github.com.helper", "store"], "credential helper específico"),
                (["git", "config", "http.https://github.com.extraheader", f"Authorization: Basic {base64.b64encode(f'{github_user}:{pat_token}'.encode()).decode()}"], "extraheader auth"),
                (["git", "config", "http.https://github.com.proxy", ""], "clear proxy"),
                (["git", "config", "core.askPass", "echo"], "askPass"),
            ]
            
            for args, desc in config_steps:
                rc = self._run_cmd(args, cwd=project_path)
                if rc != 0:
                    self.worker_queue.put(("log", f"⚠️ Error configurando {desc}"))

            # Configurar origin
            self._ensure_origin(project_path, origin_url)
            
            # Verificar que la configuración funciona
            self.worker_queue.put(("log", "✅ Credenciales configuradas con PAT token"))
            return True
            
        elif method == "gh":
            # Mantener lógica existente para GitHub CLI
            return self._setup_gh_credentials(project_path)
        elif method == "ssh":
            self.worker_queue.put(("log", "✅ Usando autenticación SSH"))
            return True
            
        return True

    def _setup_gh_credentials(self, project_path):
        """Configuración para GitHub CLI"""
        if not self._exe_exists("gh"):
            self.worker_queue.put(("log", "❌ GitHub CLI no disponible"))
            return False
            
        if not self._gh_auth_status_ok():
            pat_token = self.pat_token_var.get().strip()
            if pat_token:
                self.worker_queue.put(("log", "🔐 Autenticando GitHub CLI con token…"))
                if self._gh_login_with_token(pat_token):
                    self.worker_queue.put(("log", "✅ GitHub CLI autenticado"))
                else:
                    self.worker_queue.put(("log", "❌ No se pudo autenticar GitHub CLI"))
                    return False
            else:
                self.worker_queue.put(("log", "❌ No hay PAT token para autenticar GitHub CLI"))
                return False
        return True

    def _test_pat_token_quick(self):
        """Test rápido del PAT token sin interfaz gráfica"""
        pat_token = self.pat_token_var.get().strip()
        if not pat_token:
            return False
            
        try:
            url = "https://api.github.com/user"
            headers = {
                'Authorization': f'token {pat_token}',
                'User-Agent': 'AutoGit-App',
                'Accept': 'application/vnd.github.v3+json'
            }
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.code == 200
        except:
            return False

    # ---------- Push MEJORADO con manejo específico de autenticación ----------
    def _git_push_with_retries(self, project_path, origin="origin", branch="main"):
        attempts = 3
        method = self.auth_method_var.get().strip() or "https_pat"

        # Verificación previa crítica
        if method == "https_pat":
            pat_token = self.pat_token_var.get().strip()
            if not pat_token:
                self.worker_queue.put(("log", "❌ ERROR: No hay PAT token configurado"))
                return 1
                
            if not self._test_pat_token_quick():
                self.worker_queue.put(("log", "❌ ERROR: El PAT token no es válido"))
                self.worker_queue.put(("log", "💡 Usa Ctrl+T para verificar y configurar el token correctamente"))
                return 1

        # Configurar credenciales
        if not self._setup_credentials(project_path, method):
            return 1

        # Intentar push con diferentes estrategias
        for i in range(1, attempts + 1):
            self.worker_queue.put(("log", f"🚀 Intentando push ({i}/{attempts})…"))
            
            # Comando push con opciones para evitar prompts
            push_cmd = ["git", "push", "-u", origin, branch]
            
            rc, out = self._run_cmd_capture(push_cmd, project_path)
            
            if rc == 0:
                self.worker_queue.put(("log", "✅ Push exitoso"))
                return 0

            error_text = (out or "").lower()
            self.worker_queue.put(("log", f"❌ Push falló (intento {i}/{attempts}): {error_text}"))

            # Análisis específico del error
            if "authentication failed" in error_text or "invalid username or token" in error_text:
                self.worker_queue.put(("log", "🔐 ERROR DE AUTENTICACIÓN CRÍTICO"))
                self.worker_queue.put(("log", "💡 El PAT token es inválido o no tiene permisos 'repo'"))
                self.worker_queue.put(("log", "💡 Ve a GitHub Settings > Tokens y crea un nuevo PAT con permisos 'repo'"))
                break  # No reintentar si es error de autenticación
                
            elif "non-fast-forward" in error_text or "updates were rejected" in error_text:
                self.worker_queue.put(("log", "🔄 Conflicto de historial, intentando sincronizar…"))
                if self._sync_with_remote(project_path):
                    continue  # Reintentar después de sincronizar
                else:
                    break
                    
            elif "large files" in error_text or "gh001" in error_text:
                self.worker_queue.put(("log", "📦 Detectados archivos grandes, limpiando…"))
                if self._handle_large_files(project_path):
                    continue  # Reintentar después de limpiar
                else:
                    break
                    
            else:
                # Error genérico, esperar y reintentar
                if i < attempts:
                    wait_time = 2 * i
                    self.worker_queue.put(("log", f"⏳ Esperando {wait_time}s antes de reintentar…"))
                    time.sleep(wait_time)

        self.worker_queue.put(("log", "❌ Todos los intentos de push fallaron"))
        return 1

    def _handle_large_files(self, project_path):
        """Manejo mejorado de archivos grandes"""
        large_files = self._scan_large_files(project_path)
        if large_files:
            self._append_gitignore_patterns(project_path, large_files)
            self._untrack_list(project_path, large_files)
            self._run_cmd(["git", "add", ".gitignore"], cwd=project_path)
            self._run_cmd(["git", "commit", "--amend", "-C", "HEAD"], cwd=project_path)
            return True
        return False

    # ---------- Helpers de subprocess MEJORADOS ----------
    def _popen_capture_any(self, args, cwd=None, env=None, timeout=None):
        """Versión mejorada con timeout y manejo de errores"""
        si, cf = self._startupinfo_flags()
        
        # Asegurar variables de entorno para deshabilitar prompts
        base_env = os.environ.copy()
        base_env.update({
            'GIT_TERMINAL_PROMPT': '0',
            'GCM_INTERACTIVE': 'Never', 
            'NO_COLOR': '1'
        })
        
        if env:
            base_env.update(env)
            
        base_env = self._ensure_utf8_in_env(base_env)
        
        try:
            p = subprocess.Popen(
                args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace",
                startupinfo=si, creationflags=cf, env=base_env
            )
            
            try:
                out, _ = p.communicate(timeout=timeout)
                return p.returncode, out
            except subprocess.TimeoutExpired:
                p.kill()
                out, _ = p.communicate()
                return 124, f"Timeout después de {timeout} segundos"
                
        except FileNotFoundError:
            return 127, f"ERROR: comando no encontrado: {args[0]}"
        except Exception as e:
            return 1, f"ERROR ejecutando {args}: {e}"

    def _popen_run_any(self, args, cwd=None, env=None):
        rc, out = self._popen_capture_any(args, cwd, env)
        if out: 
            self.worker_queue.put(("log", out.strip()))
        return rc

    # ---------- Shortcuts / About ----------
    def _bind_shortcuts(self):
        self.bind_all("<Control-r>", lambda e: self._start_pipeline())
        self.bind_all("<Control-t>", lambda e: self._test_pat_token())
        self.bind_all("<Control-d>", lambda e: self._stop_pipeline())
        self.bind_all("<Control-q>", lambda e: self.on_close())
        self.bind_all("<F1>",        lambda e: self._show_about())
        self.bind_all("<F2>",        lambda e: self._show_pat_instructions())

    def _show_about(self): 
        AboutDialog(self, self.cfg.get("version", INITIAL_VERSION))

    def _status(self, txt):
        self.status_var.set(txt); self.cfg["status_text"]=txt; safe_write_json(CONFIG_PATH, self.cfg)

    # ---------- Config handlers ----------
    def _on_bool_change(self, key, value):
        self.cfg[key]=bool(value); safe_write_json(CONFIG_PATH,self.cfg); self._bump_on_config_change(f"{key}={value}")
        self._status(f"Guardado {key} = {value}")
        if key=="autoclose_enabled":
            if value and not self.running: 
                self._schedule_autoclose()
            else: 
                self._cancel_autoclose()

    def _on_int_change(self, key, raw):
        try:
            v = int(str(raw).strip())
            v = 1 if v < 1 else (86400 if v > 86400 else v)
        except:
            v = DEFAULT_CONFIG.get(key, 60)
        self.cfg[key] = v
        safe_write_json(CONFIG_PATH, self.cfg)
        self._bump_on_config_change(f"{key}={v}")
        self._status(f"Guardado {key} = {v}")
        if key=="autoclose_seconds" and self.autoclose_var.get() and not self.running:
            self._schedule_autoclose()

    def _on_str_change(self, key, value):
        self.cfg[key]=value; safe_write_json(CONFIG_PATH,self.cfg)
        self._bump_on_config_change(f"{key}=len{len(str(value))}")
        self._status(f"Guardado {key}")

    def _on_project_path_change(self):
        if self.cfg.get("follow_exe_folder", True):
            self.cfg["project_path"] = app_dir()
            self.project_path_var.set(self.cfg["project_path"])
        else:
            self.cfg["project_path"] = self.project_path_var.get()
        safe_write_json(CONFIG_PATH, self.cfg)
        if not self.repo_name_var.get(): 
            self._autodetect_repo_name()

    def _browse_folder(self):
        if self.cfg.get("follow_exe_folder", True):
            self._status("Bloqueado por 'Usar carpeta del ejecutable'.")
            return
        path = filedialog.askdirectory(initialdir=self.project_path_var.get() or app_dir(), title="Selecciona la carpeta del proyecto")
        if path:
            self.project_path_var.set(path); self._on_project_path_change()

    def _browse_ssh_key(self):
        path = filedialog.askopenfilename(
            initialdir=os.path.expanduser("~"),
            title="Selecciona tu clave privada",
            filetypes=[("Claves", "*"), ("Todos", "*.*")]
        )
        if path:
            self.ssh_key_var.set(path)
            self._on_str_change("ssh_key_path", self.ssh_key_var.get())

    def _autodetect_repo_name(self):
        p = self.project_path_var.get().strip() or app_dir()
        repo = os.path.basename(os.path.normpath(p)) or ""
        if repo:
            self.repo_name_var.set(repo); self._on_str_change("repo_name", repo)
            self._status(f"Repo autodetectado: {repo}")

    def _bump_on_config_change(self, reason=""):
        old=self.cfg.get("version",INITIAL_VERSION); new=bump_version(old)
        self.cfg["version"]=new; safe_write_json(CONFIG_PATH,self.cfg)
        try: 
            self.version_label.config(text=f"Versión: {new}")
        except: 
            pass
        log_line(f"Version bump por cambio de config ({reason}): {old} -> {new}")

    # ---------- Log & countdown ----------
    def _append_log(self, txt):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.txt_log.insert("end", f"[{ts}] {txt}\n"); self.txt_log.see("end")
        log_line(txt)

    def _schedule_autoclose(self):
        self._cancel_autoclose()
        secs = int(self.cfg.get("autoclose_seconds", 60))
        if secs < 1: secs = 1
        self.autoclose_remaining = secs
        self.countdown_var.set(f"Auto-cierre: {self.autoclose_remaining} s")
        self.countdown_job = self.after(1000, self._tick_countdown)

    def _cancel_autoclose(self):
        if self.countdown_job is not None:
            try: 
                self.after_cancel(self.countdown_job)
            except: 
                pass
            self.countdown_job = None
        self.countdown_var.set("")

    def _tick_countdown(self):
        if not self.autoclose_var.get():
            self._cancel_autoclose(); return
        self.autoclose_remaining -= 1
        if self.autoclose_remaining <= 0:
            self.countdown_var.set("Auto-cierre: 0 s"); self.on_close(); return
        self.countdown_var.set(f"Auto-cierre: {self.autoclose_remaining} s")
        self.countdown_job = self.after(1000, self._tick_countdown)

    # ---------- Subprocess helpers ----------
    def _startupinfo_flags(self):
        si = None; cf = 0
        if os.name == "nt":
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0  # SW_HIDE
            try:
                cf = subprocess.CREATE_NO_WINDOW
            except AttributeError:
                cf = 0
        return si, cf

    def _utf8_env_overlay(self):
        return {"LC_ALL": "C.UTF-8", "LANG": "C.UTF-8", "LESSCHARSET": "utf-8"}

    def _git_env(self, project_path):
        env = os.environ.copy()
        project_path = os.path.abspath(project_path)
        env["GIT_WORK_TREE"] = project_path
        env["GIT_DIR"] = os.path.join(project_path, ".git")
        env["GIT_CEILING_DIRECTORIES"] = os.path.dirname(project_path)
        env["GIT_PAGER"] = "cat"
        env["PAGER"] = "cat"
        env["GH_PAGER"] = "cat"
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GCM_INTERACTIVE"] = "Never"
        env["NO_COLOR"] = "1"
        env.update(self._utf8_env_overlay())
        return env

    def _ensure_utf8_in_env(self, env):
        if env is None:
            env = os.environ.copy()
        env.update(self._utf8_env_overlay())
        return env

    # Helpers que NO dependen de self.running (para Test PAT / tareas sueltas)
    def _run_cmd(self, args, cwd, stream=True, env=None):
        # Permite correr comandos aunque no esté activo el pipeline (útil si se pulsó "Detener")
        si, cf = self._startupinfo_flags()
        if env is None and args and args[0] == "git" and cwd:
            env = self._git_env(cwd)
        else:
            env = self._ensure_utf8_in_env(env)
        try:
            p = subprocess.Popen(
                args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace",
                startupinfo=si, creationflags=cf, env=env
            )
            if stream:
                for line in iter(p.stdout.readline, ""):
                    if line: self.worker_queue.put(("log", line.rstrip("\r\n")))
                p.wait(); return p.returncode
            else:
                out = p.communicate()[0]
                if out: self.worker_queue.put(("log", out.strip()))
                return p.returncode
        except FileNotFoundError:
            self.worker_queue.put(("log", f"ERROR: comando no encontrado: {args[0]}")); return 127
        except Exception as e:
            self.worker_queue.put(("log", f"ERROR ejecutando {args}: {e}")); return 1

    def _run_cmd_capture(self, args, cwd, env=None):
        if not self.running: return (1, "")
        si, cf = self._startupinfo_flags()
        if env is None and args and args[0] == "git" and cwd:
            env = self._git_env(cwd)
        else:
            env = self._ensure_utf8_in_env(env)
        try:
            p = subprocess.Popen(
                args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace",
                startupinfo=si, creationflags=cf, env=env
            )
            out, _ = p.communicate()
            if out: self.worker_queue.put(("log", out.strip()))
            return p.returncode, out
        except Exception as e:
            txt = f"ERROR ejecutando {args}: {e}"
            self.worker_queue.put(("log", txt)); return (1, txt)

    def _run_check_output(self, args, cwd=None, env=None):
        si, cf = self._startupinfo_flags()
        if env is None and args and args[0] == "git" and cwd:
            env = self._git_env(cwd)
        else:
            env = self._ensure_utf8_in_env(env)
        return subprocess.check_output(
            args, cwd=cwd, text=True, encoding="utf-8", errors="replace",
            stderr=subprocess.DEVNULL, startupinfo=si, creationflags=cf, env=env
        )

    # ---------- Git helpers ----------
    def _is_git_repo(self, path):
        si, cf = self._startupinfo_flags()
        try:
            rc = subprocess.call(
                ["git","rev-parse","--is-inside-work-tree"], cwd=path,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env=self._git_env(path), startupinfo=si, creationflags=cf
            )
            return rc == 0
        except Exception: return False

    def _git_toplevel(self, path):
        try: return self._run_check_output(["git","rev-parse","--show-toplevel"], cwd=path).strip()
        except: return ""

    def _remote_url(self, path):
        try: return self._run_check_output(["git","remote","get-url","origin"], cwd=path).strip()
        except: return ""

    def _build_origin(self, method, github_user, repo):
        if method == "ssh":
            return f"git@github.com:{github_user}/{repo}.git"
        elif method == "https_pat":
            pat_token = self.pat_token_var.get().strip()
            if pat_token:
                return f"https://{github_user}:{pat_token}@github.com/{github_user}/{repo}.git"
            else:
                return f"https://github.com/{github_user}/{repo}.git"
        else:  # gh
            return f"https://github.com/{github_user}/{repo}.git"

    def _ensure_origin(self, path, url):
        current = self._remote_url(path)
        if not current:
            self.worker_queue.put(("log", f"Agregando origin -> {url}"))
            self._run_cmd(["git","remote","add","origin", url], cwd=path)
        elif current.lower()!=url.lower():
            self.worker_queue.put(("log", f"Actualizando origin: {current} -> {url}"))
            self._run_cmd(["git","remote","set-url","origin", url], cwd=path)
        else:
            self.worker_queue.put(("log", f"Origin ya configurado: {current}"))

    def _exe_exists(self, name):
        for p in os.environ.get("PATH","").split(os.pathsep):
            full=os.path.join(p, name + (".exe" if os.name=="nt" else ""))
            if os.path.isfile(full): return True
        return False

    def _remote_exists(self, user, repo):
        if not self._exe_exists("gh"): return False
        si, cf = self._startupinfo_flags()
        env = self._ensure_utf8_in_env(None)
        try:
            subprocess.check_output(["gh","repo","view", f"{user}/{repo}"],
                                    text=True, encoding="utf-8", errors="replace",
                                    stderr=subprocess.DEVNULL, startupinfo=si, creationflags=cf, env=env)
            return True
        except subprocess.CalledProcessError: return False
        except Exception: return False

    def _gh_auth_status_ok(self):
        if not self._exe_exists("gh"): return False
        si, cf = self._startupinfo_flags()
        env = self._ensure_utf8_in_env(None)
        try:
            subprocess.check_output(["gh","auth","status"], text=True, encoding="utf-8", errors="replace",
                                    stderr=subprocess.DEVNULL, startupinfo=si, creationflags=cf, env=env)
            return True
        except Exception: return False

    def _gh_login_with_token(self, token):
        if not self._exe_exists("gh"): return False
        if self._gh_auth_status_ok(): return True
        si, cf = self._startupinfo_flags()
        env = self._ensure_utf8_in_env(None)
        try:
            p = subprocess.Popen(["gh","auth","login","--with-token"],
                                 text=True, encoding="utf-8", errors="replace",
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 startupinfo=si, creationflags=cf, env=env)
            p.communicate(input=token+"\n", timeout=30)
            return p.returncode == 0
        except Exception as e:
            self.worker_queue.put(("log", f"ERROR gh auth login: {e}")); return False

    def _create_remote(self, owner_repo, project_path):
        """Crea el repo remoto usando GitHub CLI con autenticación por token"""
        if not self._exe_exists("gh"): 
            self.worker_queue.put(("log", "GitHub CLI no disponible, no se puede crear repo remoto"))
            return False
        # Verificar autenticación primero
        if not self._gh_auth_status_ok():
            pat_token = self.pat_token_var.get().strip()
            if pat_token:
                self.worker_queue.put(("log", "Autenticando GitHub CLI con token…"))
                if not self._gh_login_with_token(pat_token):
                    self.worker_queue.put(("log", "❌ No se pudo autenticar GitHub CLI"))
                    return False
            else:
                self.worker_queue.put(("log", "❌ No hay PAT token para autenticar GitHub CLI"))
                return False
        self.worker_queue.put(("log", f"Creando repo remoto: {owner_repo} (public)…"))
        rc = self._run_cmd(["gh", "repo", "create", owner_repo, "--public", "--confirm"], cwd=project_path)
        if rc == 0:
            self._ensure_origin(project_path, self._build_origin("gh", owner_repo.split("/")[0], owner_repo.split("/")[1]))
            return True
        return False

    def _save_pat_in_credential_manager(self, user, token):
        self.worker_queue.put(("log", "PAT no se persiste automáticamente (stub)."))

    # --- .gitignore / untrack / tamaño ---
    def _ensure_gitignore(self, project_path):
        path = os.path.join(project_path, ".gitignore"); existing = []
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    existing = [ln.rstrip("\n") for ln in f.readlines()]
            except: existing=[]
        merged = existing[:]; changed = False
        for ln in GITIGNORE_LINES:
            if ln not in merged: merged.append(ln); changed = True
        if changed:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n".join(merged).strip()+"\n")
                self.worker_queue.put(("log", "Actualizado .gitignore"))
            except Exception as e:
                self.worker_queue.put(("log", f"ERROR escribiendo .gitignore: {e}"))

    def _append_gitignore_patterns(self, project_path, relpaths):
        if not relpaths: return
        path = os.path.join(project_path, ".gitignore")
        current = set()
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    current = set([ln.strip() for ln in f.read().splitlines() if ln.strip()])
            except:
                current = set()
        norm_relpaths = []
        for rel in relpaths:
            rel = rel.replace("\\", "/")
            if rel and rel not in current:
                norm_relpaths.append(rel)
        if not norm_relpaths: return
        try:
            with open(path, "a", encoding="utf-8") as f:
                for rel in norm_relpaths:
                    f.write(rel + "\n")
        except Exception as e:
            self.worker_queue.put(("log", f"ERROR escribiendo .gitignore: {e}"))

    def _is_tracked(self, project_path, relpath):
        try:
            out = self._run_check_output(["git","ls-files","--error-unmatch", relpath], cwd=project_path)
            return bool(out.strip())
        except subprocess.CalledProcessError: return False
        except Exception: return False

    def _untrack_list(self, project_path, relpaths):
        removed = []
        for rel in relpaths:
            full = os.path.join(project_path, rel)
            if not os.path.exists(full):   # evita pathspec not matched
                continue
            if not self._is_tracked(project_path, rel):
                continue
            rc = self._run_cmd(["git","rm","--cached","-f", rel], cwd=project_path)
            if rc == 0: removed.append(rel)
        if removed: self.worker_queue.put(("log", "Untrack: " + ", ".join(removed)))
        return removed

    def _bytes_limit_from_cfg(self):
        try: return int(self.cfg.get("max_file_size_mb", 95)) * 1024 * 1024
        except: return 95 * 1024 * 1024

    def _scan_large_files(self, project_path):
        limit = self._bytes_limit_from_cfg(); big=[]
        for root, dirs, files in os.walk(project_path):
            if ".git" in dirs: dirs.remove(".git")
            for name in files:
                p = os.path.join(root, name)
                try:
                    if os.path.getsize(p) > limit:
                        rel = os.path.relpath(p, project_path); big.append(rel)
                except: pass
        special = "autogit.exe"; sp = os.path.join(project_path, special)
        if os.path.exists(sp):
            rel = os.path.relpath(sp, project_path)
            if rel not in big: big.append(rel)
        return big

    # --- Limpieza de HISTORIA (filter-repo / filter-branch) ---
    def _run_filter_repo(self, project_path, paths):
        try:
            args = ["git","filter-repo","--force"]
            for p in paths:
                args += ["--invert-paths","--path", p]
            rc = self._run_cmd(args, cwd=project_path)
            return rc == 0
        except Exception:
            return False

    def _worktree_dirty(self, cwd):
        try:
            si, cf = self._startupinfo_flags()
            rc1 = subprocess.call(["git","diff","--cached","--quiet"], cwd=cwd,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  env=self._git_env(cwd), startupinfo=si, creationflags=cf)
            rc2 = subprocess.call(["git","diff","--quiet"], cwd=cwd,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  env=self._git_env(cwd), startupinfo=si, creationflags=cf)
            rc3_out = self._run_check_output(["git","ls-files","--others","--exclude-standard"], cwd=cwd)
            has_untracked = bool((rc3_out or "").strip())
            return (rc1 != 0) or (rc2 != 0) or has_untracked
        except Exception:
            return True

    def _prepare_history_rewrite(self, cwd):
        if self._worktree_dirty(cwd):
            self.worker_queue.put(("log","Working tree sucio: guardando en stash…"))
            rc = self._run_cmd(["git","stash","push","-u","-m","autogit-temp-stash"], cwd=cwd)
            return rc == 0
        return False

    def _restore_after_rewrite(self, cwd, stashed):
        if stashed:
            self.worker_queue.put(("log","Restaurando cambios desde stash…"))
            self._run_cmd(["git","stash","pop"], cwd=cwd)

    def _find_paths_in_history(self, project_path, name_patterns):
        rc, out = self._run_cmd_capture(["git","rev-list","--objects","--all"], project_path)
        if rc != 0 or not out: return []
        lines = (out or "").splitlines()
        pats = [p.lower() for p in name_patterns if p]
        result = set()
        for ln in lines:
            parts = ln.split(" ", 1)
            if len(parts) != 2: continue
            rel = parts[1].strip().replace("\\", "/")
            base = os.path.basename(rel).lower()
            for pat in pats:
                if "*" in pat:
                    if pat.replace("*","") in base:
                        result.add(rel)
                else:
                    if base == pat:
                        result.add(rel)
        return sorted(result)

    def _run_filter_branch(self, project_path, paths):
        if not paths: return True
        stashed = self._prepare_history_rewrite(project_path)
        env = self._git_env(project_path)
        env["FILTER_BRANCH_SQUELCH_WARNING"] = "1"
        rm_parts = [f"git rm -q -f --cached --ignore-unmatch {p}" for p in paths]
        rm_cmd = " && ".join(rm_parts) or "echo noop"
        rc = self._run_cmd(
            ["git","filter-branch","-f","--prune-empty","--tag-name-filter","cat",
             "--index-filter", rm_cmd, "--","--all"],
            cwd=project_path, env=env
        )
        if rc != 0:
            self._restore_after_rewrite(project_path, stashed)
            return False
        self._run_cmd(["git","for-each-ref","--format=%(refname)","refs/original/"], cwd=project_path, env=env)
        self._run_cmd(["git","update-ref","-d","refs/original/refs/heads/main"], cwd=project_path, env=env)
        self._run_cmd(["git","reflog","expire","--expire=now","--all"], cwd=project_path, env=env)
        self._run_cmd(["git","gc","--prune=now","--aggressive"], cwd=project_path, env=env)
        self._restore_after_rewrite(project_path, stashed)
        return True

    def _purge_history_paths(self, project_path, patterns):
        if not patterns: return True
        names, routes = [], []
        for p in patterns:
            if ("/" in p) or ("\\" in p): routes.append(p.replace("\\","/"))
            else: names.append(p)
        to_purge = []
        if names:
            hist_routes = self._find_paths_in_history(project_path, names)
            to_purge.extend(hist_routes)
        to_purge.extend(routes)
        expanded, seen = [], set()
        for r in to_purge:
            if r not in seen:
                seen.add(r); expanded.append(r)
        if not expanded:
            self.worker_queue.put(("log", "No se encontraron rutas históricas a purgar."))
            return True
        self.worker_queue.put(("log", "Rutas a purgar del historial: " + ", ".join(expanded)))
        ok = self._run_filter_repo(project_path, expanded)
        if not ok:
            self.worker_queue.put(("log", "filter-repo no disponible o falló; usando filter-branch (lento)…"))
            ok = self._run_filter_branch(project_path, expanded)
        if ok:
            self.worker_queue.put(("log", "Limpieza de historia completada."))
        else:
            self.worker_queue.put(("log", "ERROR: no se pudo limpiar la historia."))
        return ok

    # --- Auto-sync con remoto cuando push es rechazado ---
    def _sync_with_remote(self, project_path):
        self.worker_queue.put(("log", "Intentando sincronizar con remoto (fetch/pull)…"))
        self._run_cmd(["git","fetch","origin","main"], cwd=project_path)
        self._run_cmd(["git","branch","--set-upstream-to=origin/main","main"], cwd=project_path)

        rc = self._run_cmd(["git","pull","--rebase","--autostash","origin","main"], cwd=project_path)
        if rc == 0:
            self.worker_queue.put(("log", "pull --rebase exitoso."))
            return True

        self._run_cmd(["git","rebase","--abort"], cwd=project_path)
        rc = self._run_cmd(["git","pull","origin","main","--allow-unrelated-histories","--no-edit"], cwd=project_path)
        if rc == 0:
            self.worker_queue.put(("log", "pull con --allow-unrelated-histories exitoso."))
            return True

        self._run_cmd(["git","merge","--abort"], cwd=project_path)
        rc = self._run_cmd(["git","pull","-s","recursive","-X","ours","origin","main",
                            "--allow-unrelated-histories","--no-edit"], cwd=project_path)
        if rc == 0:
            self.worker_queue.put(("log", "pull con estrategia -X ours exitoso (se conserva local)."))
            return True

        self._run_cmd(["git","merge","--abort"], cwd=project_path)
        self._run_cmd(["git","rebase","--abort"], cwd=project_path)
        self.worker_queue.put(("log", "No se pudo sincronizar automáticamente con el remoto."))
        return False

    # ---------- Locks ----------
    def _remove_index_lock_if_any(self, path):
        top = self._git_toplevel(path)
        if not top: return False
        lock = os.path.join(top, ".git", "index.lock")
        if os.path.exists(lock):
            try:
                os.remove(lock); self.worker_queue.put(("log", f"Se removió lock: {lock}"))
                return True
            except Exception as e:
                self.worker_queue.put(("log", f"ERROR eliminando lock {lock}: {e}"))
        return False

    # ---------- Git UTF-8 config & commit message check ----------
    def _ensure_git_utf8_config(self, project_path):
        steps = [
            (["git","config","i18n.commitEncoding","utf-8"], "i18n.commitEncoding=utf-8"),
            (["git","config","i18n.logOutputEncoding","utf-8"], "i18n.logOutputEncoding=utf-8"),
            (["git","config","gui.encoding","utf-8"], "gui.encoding=utf-8"),
            (["git","config","core.quotepath","false"], "core.quotepath=false"),
        ]
        for args, _ in steps:
            self._run_cmd(args, cwd=project_path)

    def _read_last_commit_message(self, project_path):
        try:
            msg = self._run_check_output(["git","log","-1","--pretty=%B"], cwd=project_path)
            return msg.strip()
        except Exception:
            return ""

    def _maybe_fix_last_commit_message(self, project_path):
        last = self._read_last_commit_message(project_path)
        if not last: return
        fixed = _unmojibake_if_needed(last)
        if fixed != last:
            self.worker_queue.put(("log", f"Corregido mensaje de commit mojibake:\n  Antes: {last}\n  Ahora:  {fixed}"))
            self._run_cmd(["git","commit","--amend","-m", fixed], cwd=project_path)

    # ---------- Pipeline principal (CON MEJORAS) ----------
    def _worker_pipeline(self, project_path, repo_name, commit_msg, create_readme):
        try:
            self.worker_queue.put(("stat","Verificando herramientas…"))
            
            if not self._exe_exists("git"):
                self.worker_queue.put(("log","❌ ERROR: Git no está en PATH."))
                self.worker_queue.put(("done",None))
                return
            
            git_name = self.git_user_name_var.get().strip()
            git_mail = self.git_user_email_var.get().strip()
            method   = self.auth_method_var.get().strip() or "https_pat"
            gh_user  = self.github_user_var.get().strip()

            # VERIFICACIÓN CRÍTICA ANTES DE INICIAR
            if method == "https_pat":
                pat_token = self.pat_token_var.get().strip()
                if not pat_token:
                    self.worker_queue.put(("log","❌ ERROR: No hay PAT token configurado"))
                    self.worker_queue.put(("log","💡 Usa Ctrl+T para testear el token"))
                    self.worker_queue.put(("done",None))
                    return
                    
                # Test rápido del PAT antes de continuar
                self.worker_queue.put(("log","🔐 Verificando PAT token antes de iniciar…"))
                if not self._test_pat_token_quick():
                    self.worker_queue.put(("log","❌ ERROR: El PAT token no es válido"))
                    self.worker_queue.put(("log","💡 Usa Ctrl+T para diagnosticar el problema"))
                    self.worker_queue.put(("done",None))
                    return

            first_time = not self._is_git_repo(project_path)

            # 1) INIT/CONFIG
            if first_time:
                self.worker_queue.put(("log","🆕 Inicializando repositorio Git…"))
                if self._run_cmd(["git","init"], cwd=project_path) != 0:
                    self.worker_queue.put(("log","ERROR en git init")); self.worker_queue.put(("done",None)); return
            
            identity_steps = [
                (["git","config","user.name", git_name], "git config user.name"),
                (["git","config","user.email", git_mail], "git config user.email"),
                (["git","config","core.autocrlf","true"], "git config core.autocrlf"),
                (["git","config","core.filemode","false"], "git config core.filemode"),
                (["git","config","core.longpaths","true"], "git config core.longpaths"),
                (["git","config","core.safecrlf","false"], "git config core.safecrlf"),
            ]
            for args, label in identity_steps:
                if self._run_cmd(args, cwd=project_path)!=0:
                    self.worker_queue.put(("log", f"ERROR en paso: {label}")); self.worker_queue.put(("done",None)); return
            
            self._ensure_git_utf8_config(project_path)
            self._run_cmd(["git","branch","-M","main"], cwd=project_path)

            # 2) .gitignore + untrack + grandes
            self._ensure_gitignore(project_path)
            exe_name = os.path.basename(sys.executable) if getattr(sys,'frozen',False) else None
            to_untrack = ["config.json","log.txt","config_autogit.json","log_autogit.txt"]
            if exe_name: to_untrack.append(exe_name)
            self._untrack_list(project_path, to_untrack)
            large = self._scan_large_files(project_path)
            if large:
                self._append_gitignore_patterns(project_path, large)
                self._untrack_list(project_path, large)

            # 3) README inicial si aplica
            if first_time and self.cfg.get("create_readme_if_missing", True):
                readme_path = os.path.join(project_path, "README.md")
                if not os.path.exists(readme_path):
                    with open(readme_path,"w",encoding="utf-8") as f:
                        f.write(f"# {repo_name}\n\nProyecto {repo_name}.\n")

            # 4) ALWAYS add & commit ANTES del remoto
            self.worker_queue.put(("log","📦 Agregando archivos al staging…"))
            rc = self._run_cmd(["git","add","."], cwd=project_path)
            if rc != 0:
                if self._remove_index_lock_if_any(project_path):
                    rc = self._run_cmd(["git","add","."], cwd=project_path)
                if rc != 0:
                    self.worker_queue.put(("log","ERROR en git add .")); self.worker_queue.put(("done",None)); return

            # Verificar si hay cambios para commit
            si, cf = self._startupinfo_flags()
            rc_diff_cached = subprocess.call(
                ["git","diff","--cached","--quiet"],
                cwd=project_path,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=self._git_env(project_path),
                startupinfo=si,
                creationflags=cf
            )

            if first_time or rc_diff_cached != 0:
                commit_msg_use = (self.commit_message_var.get().strip() or 
                                 "Primer commit" if first_time else "Actualización automática")
                if first_time and rc_diff_cached == 0:
                    args = ["git","commit","-m", commit_msg_use, "--allow-empty"]
                else:
                    args = ["git","commit","-m", commit_msg_use]
                self.worker_queue.put(("log",f"💾 Creando commit: {commit_msg_use}"))
                if self._run_cmd(args, cwd=project_path) != 0:
                    self.worker_queue.put(("log","ERROR en commit.")); self.worker_queue.put(("done",None)); return
            else:
                self.worker_queue.put(("log","✅ No hay cambios para commitear."))

            self._maybe_fix_last_commit_message(project_path)

            # 5) REMOTO
            origin_url = self._build_origin(method, gh_user, repo_name)
            remote_exists = False
            if self._exe_exists("gh") and gh_user and repo_name:
                remote_exists = self._remote_exists(gh_user, repo_name)
            if not remote_exists:
                self.worker_queue.put(("log","🌐 Repositorio remoto no existe, creando…"))
                owner_repo = f"{gh_user}/{repo_name}"
                if self._exe_exists("gh"):
                    if not self._create_remote(owner_repo, project_path):
                        self.worker_queue.put(("log","⚠️ No se pudo crear el repo remoto automáticamente"))
                        self.worker_queue.put(("log","💡 Crea el repo manualmente en GitHub.com"))
                else:
                    self.worker_queue.put(("log","ℹ️ GitHub CLI no disponible, asumiendo repo remoto existe"))
            else:
                self.worker_queue.put(("log","✅ Repositorio remoto existe"))

            self._ensure_origin(project_path, origin_url)

            # 6) PUSH
            self.worker_queue.put(("log","🚀 Subiendo cambios al repositorio remoto…"))
            rc = self._git_push_with_retries(project_path, "origin", "main")
            if rc != 0:
                self.worker_queue.put(("log","❌ ERROR en push. Revisa credenciales y conexión.")); self.worker_queue.put(("done",None)); return

            self.worker_queue.put(("stat","✅ Pipeline completado exitosamente"))

        except Exception as e:
            self.worker_queue.put(("log", f"❌ ERROR pipeline: {e}"))
            self.worker_queue.put(("log", traceback.format_exc()))
        finally:
            self.worker_queue.put(("done", None))

    # ---------- Orquestación ----------
    def _start_pipeline(self):
        if self.running: self._status("Ya hay un proceso en ejecución."); return
        proj = self.project_path_var.get().strip()
        repo = self.repo_name_var.get().strip()
        if not proj or not os.path.isdir(proj):
            self._status("Ruta del proyecto inválida."); self._append_log("ERROR: ruta de proyecto inválida."); return
        if not repo:
            self._autodetect_repo_name(); repo=self.repo_name_var.get().strip()
            if not repo: self._status("No se pudo determinar el nombre del repo."); return

        method = self.auth_method_var.get().strip() or "https_pat"
        if method == "https_pat" and not self.pat_token_var.get().strip():
            self._status("ERROR: Configura un PAT token primero (Ctrl+T para testear)")
            messagebox.showerror("PAT Token Requerido", 
                               "Debes configurar un Personal Access Token (PAT) de GitHub.\n\n" 
                               "Presiona Ctrl+T para testear el token o F2 para instrucciones.")
            return

        self.running=True; self.btn_run.config(state="disabled"); self.btn_stop.config(state="normal")
        self._status("Ejecutando pipeline…")
        self._append_log(f"Iniciando pipeline en: {proj} (repo: {repo})")
        self._cancel_autoclose()
        t=threading.Thread(
            target=self._worker_pipeline,
            args=(proj,repo,self.commit_message_var.get().strip() or "Actualización automática", self.create_readme_var.get()),
            daemon=True
        )
        t.start()

    def _stop_pipeline(self):
        if not self.running: self._status("No hay proceso en ejecución."); return
        self.running=False; self._append_log("Solicitud de detener recibida… (termina el paso actual)")

    def _poll_worker_queue(self):
        try:
            while True:
                kind, payload = self.worker_queue.get_nowait()
                if kind=="log":    self._append_log(payload)
                elif kind=="stat": self._status(payload)
                elif kind=="done":
                    self.running=False; self.btn_run.config(state="normal"); self.btn_stop.config(state="disabled")
                    if self.autoclose_var.get(): self._schedule_autoclose()
        except queue.Empty:
            pass
        self.after(120, self._poll_worker_queue)

    def on_close(self):
        try:
            self.cfg["window_geometry"]=self.geometry(); safe_write_json(CONFIG_PATH,self.cfg)
        except: pass
        log_line("Aplicación cerrada por el usuario."); self.destroy()

# ---------- Main ----------
if __name__=="__main__":
    try:
        if not os.path.exists(LOG_PATH): open(LOG_PATH,"w",encoding="utf-8").close()
        log_line("=== Lanzamiento de la aplicación (v0.2.6 - PAT FIX) ===")
    except Exception as e:
        print("No se pudo crear log.txt:", e)
    app = App(); app.mainloop()