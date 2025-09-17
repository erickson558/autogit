# -*- coding: utf-8 -*-
"""
Git Helper GUI – v0.0.8
- Guarda en config.json TODOS los campos editables de la GUI (incluye PAT token).
- Status bar fija y visible siempre (con countdown a la derecha).
- Mantiene: ocultar consolas, crear repo remoto si no existe, manejo index.lock,
  autenticación GH/HTTPS+PAT/SSH, autocierre pausado durante pipeline, logs UTF-8.
"""

import os, sys, json, hashlib, threading, datetime, queue, traceback, subprocess

try:
    import tkinter as tk
    from tkinter import ttk, filedialog
except Exception as e:
    print("Tkinter no disponible:", e); sys.exit(1)

APP_NAME = "Git Helper GUI"
INITIAL_VERSION = "0.0.1"

def app_dir():
    return os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))

CONFIG_PATH = os.path.join(app_dir(), "config.json")
LOG_PATH    = os.path.join(app_dir(), "log.txt")

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

# ---------- Config por defecto ----------
DEFAULT_CONFIG = {
    "version": INITIAL_VERSION,
    "last_code_hash": "",
    "window_geometry": "1040x720+100+100",
    "autostart": False,
    "autoclose_enabled": False,
    "autoclose_seconds": 60,
    "status_text": "Listo.",
    "shortcuts_enabled": True,

    # Proyecto / repo
    "project_path": app_dir(),
    "repo_name": "",

    # Git identity
    "git_user_name": "erickson558",
    "git_user_email": "erickson558@hotmail.com",

    # Autenticación: "gh" | "https_pat" | "ssh"
    "auth_method": "gh",
    "github_user": "erickson558",

    # HTTPS + PAT (ahora también guardamos el token por petición)
    "pat_username": "github",
    "pat_token": "",  # ⚠️ guardado en texto plano por solicitud explícita
    "pat_save_in_credential_manager": True,

    # SSH
    "ssh_key_path": "",

    # Commit / flujo
    "commit_message": "Actualización automática",
    "create_readme_if_missing": True
}

# ---------- About ----------
class AboutDialog(tk.Toplevel):
    def __init__(self, master, version):
        super().__init__(master)
        self.title("Acerca de"); self.resizable(False, False)
        self.geometry("+{}+{}".format(master.winfo_rootx()+80, master.winfo_rooty()+80))
        self.configure(bg="#101418")
        frm = tk.Frame(self, bg="#101418"); frm.pack(padx=16, pady=16)
        tk.Label(frm, text=f"{APP_NAME}\n\n{version} creado por Synyster Rick, {datetime.datetime.now().year} Derechos Reservados",
                 fg="#E6EDF3", bg="#101418", font=("Segoe UI", 10)).pack(pady=(0,12))
        ttk.Button(frm, text="Cerrar (Esc)", command=self.destroy).pack()
        self.bind("<Escape>", lambda e: self.destroy())

# ---------- App ----------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME); self.configure(bg="#0B0F14")

        # Cargar config + bump si cambió el código
        self.cfg = safe_read_json(CONFIG_PATH, DEFAULT_CONFIG.copy())
        code_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
        h = file_hash(code_path)
        if h and h != self.cfg.get("last_code_hash",""):
            self.cfg["version"] = bump_version(self.cfg.get("version", INITIAL_VERSION))
            self.cfg["last_code_hash"] = h
            safe_write_json(CONFIG_PATH, self.cfg)
            log_line(f"Version bump por cambio de código: {self.cfg['version']}")

        self._build_style()
        self._build_menu()
        self._build_widgets()

        # Restaurar geometría
        try: self.geometry(self.cfg.get("window_geometry") or DEFAULT_CONFIG["window_geometry"])
        except: self.geometry(DEFAULT_CONFIG["window_geometry"])

        self.worker_thread = None
        self.worker_queue  = queue.Queue()
        self.running = False
        self.countdown_job = None
        self.autoclose_remaining = 0

        if self.cfg.get("shortcuts_enabled", True): self._bind_shortcuts()
        self.after(100, self._poll_worker_queue)

        # Si Autoclose ON y no corriendo, arranca countdown visible
        if self.cfg.get("autoclose_enabled", False):
            self._schedule_autoclose()

        if self.autostart_var.get():
            self._start_pipeline()

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
        menubar = tk.Menu(self, tearoff=0)
        self.config(menu=menubar)
        m_app = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Aplicación", menu=m_app, underline=0)
        m_app.add_command(label="Ejecutar pipeline", accelerator="Ctrl+R", command=self._start_pipeline)
        m_app.add_command(label="Detener", accelerator="Ctrl+D", command=self._stop_pipeline)
        m_app.add_separator()
        m_app.add_command(label="Salir", accelerator="Ctrl+Q", command=self.on_close)
        m_help = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Ayuda", menu=m_help, underline=0)
        m_help.add_command(label="About", accelerator="F1", command=self._show_about)

    def _build_widgets(self):
        top = ttk.Frame(self); top.pack(fill="x", padx=16, pady=12)
        ttk.Label(top, text=APP_NAME, font=("Segoe UI Semibold", 14)).pack(side="left")
        self.version_label = ttk.Label(top, text=f"Versión: {self.cfg.get('version', INITIAL_VERSION)}",
                                       font=("Segoe UI Semibold", 10))
        self.version_label.pack(side="right")

        body = ttk.Frame(self); body.pack(fill="both", expand=True, padx=16, pady=8)

        # Línea A: Autostart / Autocerrar
        rowA = ttk.Frame(body); rowA.pack(fill="x", pady=(2,2))
        self.autostart_var = tk.BooleanVar(value=self.cfg.get("autostart", False))
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

        # Línea B: Proyecto y repo
        rowB = ttk.Frame(body); rowB.pack(fill="x", pady=(8,4))
        ttk.Label(rowB, text="Ruta del proyecto:").pack(side="left")
        self.project_path_var = tk.StringVar(value=self.cfg.get("project_path", app_dir()))
        e_path = ttk.Entry(rowB, width=64, textvariable=self.project_path_var)
        e_path.pack(side="left", padx=6, fill="x", expand=True)
        e_path.bind("<FocusOut>", lambda e: self._on_project_path_change())
        e_path.bind("<Return>",   lambda e: self._on_project_path_change())
        ttk.Button(rowB, text="Examinar…", command=self._browse_folder).pack(side="left", padx=(6,0))

        rowC = ttk.Frame(body); rowC.pack(fill="x", pady=(4,4))
        ttk.Label(rowC, text="Nombre del repo (GitHub):").pack(side="left")
        self.repo_name_var = tk.StringVar(value=self.cfg.get("repo_name",""))
        e_repo = ttk.Entry(rowC, width=40, textvariable=self.repo_name_var)
        e_repo.pack(side="left", padx=6)
        e_repo.bind("<FocusOut>", lambda e: self._on_str_change("repo_name", self.repo_name_var.get()))
        e_repo.bind("<Return>",   lambda e: self._on_str_change("repo_name", self.repo_name_var.get()))
        ttk.Button(rowC, text="Autodetectar", command=self._autodetect_repo_name).pack(side="left", padx=(6,0))

        # Línea D: Identidad Git
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

        # Línea E: Autenticación
        rowE = ttk.LabelFrame(body, text="Autenticación"); rowE.pack(fill="x", pady=(10,6))
        ttk.Label(rowE, text="Método:").grid(row=0, column=0, sticky="w", padx=6, pady=6)
        self.auth_method_var = tk.StringVar(value=self.cfg.get("auth_method","gh"))
        cb_auth = ttk.Combobox(rowE, textvariable=self.auth_method_var, state="readonly",
                               values=["gh","https_pat","ssh"], width=12)
        cb_auth.grid(row=0, column=1, sticky="w", padx=6, pady=6)
        cb_auth.bind("<<ComboboxSelected>>", lambda e: self._on_str_change("auth_method", self.auth_method_var.get()))

        ttk.Label(rowE, text="Usuario GitHub:").grid(row=0, column=2, sticky="w", padx=(16,6))
        self.github_user_var = tk.StringVar(value=self.cfg.get("github_user",""))
        e_ghu = ttk.Entry(rowE, width=22, textvariable=self.github_user_var)
        e_ghu.grid(row=0, column=3, sticky="w", padx=6, pady=6)
        e_ghu.bind("<FocusOut>", lambda e: self._on_str_change("github_user", self.github_user_var.get()))
        e_ghu.bind("<Return>",   lambda e: self._on_str_change("github_user", self.github_user_var.get()))

        # HTTPS + PAT
        ttk.Label(rowE, text="PAT usuario:").grid(row=1, column=0, sticky="w", padx=6, pady=6)
        self.pat_user_var = tk.StringVar(value=self.cfg.get("pat_username","github"))
        e_pu = ttk.Entry(rowE, width=20, textvariable=self.pat_user_var)
        e_pu.grid(row=1, column=1, sticky="w", padx=6, pady=6)
        e_pu.bind("<FocusOut>", lambda e: self._on_str_change("pat_username", self.pat_user_var.get()))
        e_pu.bind("<Return>",   lambda e: self._on_str_change("pat_username", self.pat_user_var.get()))

        ttk.Label(rowE, text="PAT token:").grid(row=1, column=2, sticky="w", padx=(16,6))
        self._pat_shown = False
        self.pat_token_var = tk.StringVar(value=self.cfg.get("pat_token",""))
        self.e_pt = ttk.Entry(rowE, width=30, textvariable=self.pat_token_var, show="•")
        self.e_pt.grid(row=1, column=3, sticky="w", padx=6, pady=6)
        def toggle_pat():
            self._pat_shown = not self._pat_shown
            self.e_pt.config(show="" if self._pat_shown else "•")
        ttk.Button(rowE, text="Mostrar", width=10, command=toggle_pat).grid(row=1, column=4, sticky="w", padx=6)
        # guardado inmediato al escribir
        self.e_pt.bind("<KeyRelease>", lambda e: self._on_str_change("pat_token", self.pat_token_var.get()))

        self.pat_save_var = tk.BooleanVar(value=self.cfg.get("pat_save_in_credential_manager", True))
        ttk.Checkbutton(rowE, text="Guardar token en Credential Manager (Windows)",
                        variable=self.pat_save_var,
                        command=lambda: self._on_bool_change("pat_save_in_credential_manager", self.pat_save_var.get())
                        ).grid(row=2, column=0, columnspan=3, sticky="w", padx=6, pady=4)

        # SSH
        ttk.Label(rowE, text="Clave SSH (opcional):").grid(row=3, column=0, sticky="w", padx=6, pady=6)
        self.ssh_key_var = tk.StringVar(value=self.cfg.get("ssh_key_path",""))
        e_sk = ttk.Entry(rowE, width=40, textvariable=self.ssh_key_var)
        e_sk.grid(row=3, column=1, columnspan=2, sticky="we", padx=6, pady=6)
        e_sk.bind("<FocusOut>", lambda e: self._on_str_change("ssh_key_path", self.ssh_key_var.get()))
        e_sk.bind("<Return>",   lambda e: self._on_str_change("ssh_key_path", self.ssh_key_var.get()))
        ttk.Button(rowE, text="Examinar…", command=self._browse_ssh_key).grid(row=3, column=3, sticky="w", padx=6)
        for i in range(5):
            rowE.grid_columnconfigure(i, weight=1)

        # Línea F: Commit + README
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

        # Botones
        rowG = ttk.Frame(body); rowG.pack(fill="x", pady=(12,6))
        self.btn_run  = ttk.Button(rowG, text="Ejecutar pipeline (Ctrl+R)", command=self._start_pipeline)
        self.btn_stop = ttk.Button(rowG, text="Detener (Ctrl+D)", command=self._stop_pipeline, state="disabled")
        self.btn_exit = ttk.Button(rowG, text="Salir (Ctrl+Q)", command=self.on_close)
        self.btn_run.pack(side="left"); self.btn_stop.pack(side="left", padx=8); self.btn_exit.pack(side="right")

        # Log visual
        logf = ttk.Frame(body); logf.pack(fill="both", expand=True, pady=(8,8))
        self.txt_log = tk.Text(logf, height=14, bg="#0F1620", fg="#C9D1D9", insertbackground="#C9D1D9", relief="flat", wrap="word")
        self.txt_log.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(logf, orient="vertical", command=self.txt_log.yview); sb.pack(side="right", fill="y")
        self.txt_log.configure(yscrollcommand=sb.set)

        # Status bar SIEMPRE visible, al final de la ventana
        status = tk.Frame(self, bg="#0A0E12", bd=1, relief="sunken", height=24)
        status.pack(side="bottom", fill="x")
        status.pack_propagate(False)
        self.status_var = tk.StringVar(value=self.cfg.get("status_text","Listo."))
        ttk.Label(status, textvariable=self.status_var, style="Status.TLabel").pack(side="left", padx=10)
        self.countdown_var = tk.StringVar(value="")
        ttk.Label(status, textvariable=self.countdown_var, style="Status.TLabel").pack(side="right", padx=10)

    # ---------- Shortcuts / About ----------
    def _bind_shortcuts(self):
        self.bind_all("<Control-r>", lambda e: self._start_pipeline())
        self.bind_all("<Control-d>", lambda e: self._stop_pipeline())
        self.bind_all("<Control-q>", lambda e: self.on_close())
        self.bind_all("<F1>",        lambda e: self._show_about())

    def _show_about(self): AboutDialog(self, self.cfg.get("version", INITIAL_VERSION))
    def _status(self, txt):
        self.status_var.set(txt); self.cfg["status_text"]=txt; safe_write_json(CONFIG_PATH, self.cfg)

    # ---------- Config handlers (GUARDAN TODO) ----------
    def _on_bool_change(self, key, value):
        self.cfg[key]=bool(value); safe_write_json(CONFIG_PATH,self.cfg); self._bump_on_config_change(f"{key}={value}")
        self._status(f"Guardado {key} = {value}")
        if key=="autoclose_enabled":
            if value and not self.running: self._schedule_autoclose()
            else: self._cancel_autoclose()

    def _on_int_change(self, key, raw):
        try:
            v=int(str(raw).strip()); v=1 if v<1 else (86400 if v>86400 else v)
        except: v=DEFAULT_CONFIG.get(key,60)
        self.cfg[key]=v; safe_write_json(CONFIG_PATH,self.cfg); self._bump_on_config_change(f"{key}={v}")
        self._status(f"Guardado {key} = {v}")
        if key=="autoclose_seconds" and self.autoclose_var.get() and not self.running:
            self._schedule_autoclose()

    def _on_str_change(self, key, value):
        # A PARTIR DE ESTA VERSIÓN guardamos TODO, incl. 'pat_token' (por petición).
        self.cfg[key]=value
        safe_write_json(CONFIG_PATH,self.cfg)
        self._bump_on_config_change(f"{key}=len{len(str(value))}")
        self._status(f"Guardado {key}")

    def _on_project_path_change(self):
        self._on_str_change("project_path", self.project_path_var.get())
        if not self.repo_name_var.get(): self._autodetect_repo_name()

    def _browse_folder(self):
        path = filedialog.askdirectory(initialdir=self.project_path_var.get() or app_dir(), title="Selecciona la carpeta del proyecto")
        if path:
            self.project_path_var.set(path); self._on_project_path_change()

    def _browse_ssh_key(self):
        path = filedialog.askopenfilename(initialdir=os.path.expanduser("~"), title="Selecciona tu clave privada",
                                          filetypes=[("Claves", "*"), ("Todos", "*.*")])
        if path:
            self.ssh_key_var.set(path); self._on_str_change("ssh_key_path", path)

    def _autodetect_repo_name(self):
        p = self.project_path_var.get().strip() or app_dir()
        repo = os.path.basename(os.path.normpath(p)) or ""
        if repo:
            self.repo_name_var.set(repo); self._on_str_change("repo_name", repo)
            self._status(f"Repo autodetectado: {repo}")

    def _bump_on_config_change(self, reason=""):
        old=self.cfg.get("version",INITIAL_VERSION); new=bump_version(old)
        self.cfg["version"]=new; safe_write_json(CONFIG_PATH,self.cfg)
        self.version_label.config(text=f"Versión: {new}")
        log_line(f"Version bump por cambio de config ({reason}): {old} -> {new}")

    # ---------- Log visual ----------
    def _append_log(self, txt):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.txt_log.insert("end", f"[{ts}] {txt}\n"); self.txt_log.see("end")
        log_line(txt)

    # ---------- Countdown ----------
    def _schedule_autoclose(self):
        self._cancel_autoclose()
        secs = int(self.cfg.get("autoclose_seconds", 60))
        if secs < 1: secs = 1
        self.autoclose_remaining = secs
        self.countdown_var.set(f"Auto-cierre: {self.autoclose_remaining} s")
        self.countdown_job = self.after(1000, self._tick_countdown)

    def _cancel_autoclose(self):
        if self.countdown_job is not None:
            try: self.after_cancel(self.countdown_job)
            except: pass
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

    # ---------- Subprocess helpers (ocultos en Windows) ----------
    def _startupinfo_flags(self):
        si = None
        cf = 0
        if os.name == "nt":
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            try: cf = subprocess.CREATE_NO_WINDOW
            except AttributeError: cf = 0
        return si, cf

    def _exe_exists(self, name):
        for p in os.environ.get("PATH","").split(os.pathsep):
            full=os.path.join(p, name + (".exe" if os.name=="nt" else ""))
            if os.path.isfile(full): return True
        return False

    def _run_cmd(self, args, cwd, stream=True):
        """Ejecuta comando ocultando ventana (Windows) y capturando UTF-8."""
        if not self.running: return 1
        si, cf = self._startupinfo_flags()
        try:
            p = subprocess.Popen(
                args, cwd=cwd,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace",
                startupinfo=si, creationflags=cf
            )
            if stream:
                for line in iter(p.stdout.readline, ""):
                    if line: self.worker_queue.put(("log", line.rstrip("\r\n")))
                    if not self.running:
                        pass
                p.wait()
                return p.returncode
            else:
                out = p.communicate()[0]
                if out: self.worker_queue.put(("log", out.strip()))
                return p.returncode
        except FileNotFoundError:
            self.worker_queue.put(("log", f"ERROR: comando no encontrado: {args[0]}"))
            return 127
        except Exception as e:
            self.worker_queue.put(("log", f"ERROR ejecutando {args}: {e}"))
            return 1

    def _run_check_output(self, args, cwd=None):
        si, cf = self._startupinfo_flags()
        return subprocess.check_output(
            args, cwd=cwd, text=True, encoding="utf-8", errors="replace",
            stderr=subprocess.DEVNULL, startupinfo=si, creationflags=cf
        )

    def _is_git_repo(self, path):
        si, cf = self._startupinfo_flags()
        try:
            rc = subprocess.call(
                ["git","rev-parse","--is-inside-work-tree"], cwd=path,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                startupinfo=si, creationflags=cf
            )
            return rc == 0
        except Exception:
            return False

    def _git_toplevel(self, path):
        try:
            out = self._run_check_output(["git","rev-parse","--show-toplevel"], cwd=path).strip()
            return out
        except:
            return ""

    # ---------- Auth/Remote helpers ----------
    def _remote_url(self, path):
        try:
            out = self._run_check_output(["git","remote","get-url","origin"], cwd=path).strip()
            return out
        except: return ""

    def _build_origin(self, method, github_user, repo):
        if method == "ssh":
            return f"git@github.com:{github_user}/{repo}.git"
        else:
            return f"https://github.com/{github_user}/{repo}.git"

    def _ensure_origin(self, path, url):
        current  = self._remote_url(path)
        if not current:
            self.worker_queue.put(("log", f"Agregando origin -> {url}"))
            self._run_cmd(["git","remote","add","origin", url], cwd=path)
        elif current.lower()!=url.lower():
            self.worker_queue.put(("log", f"Actualizando origin: {current} -> {url}"))
            self._run_cmd(["git","remote","set-url","origin", url], cwd=path)

    def _remote_exists(self, user, repo):
        if not self._exe_exists("gh"): return False
        si, cf = self._startupinfo_flags()
        try:
            subprocess.check_output(["gh","repo","view", f"{user}/{repo}"],
                                    text=True, encoding="utf-8", errors="replace",
                                    stderr=subprocess.DEVNULL, startupinfo=si, creationflags=cf)
            return True
        except subprocess.CalledProcessError:
            return False
        except Exception:
            return False

    def _gh_auth_status_ok(self):
        if not self._exe_exists("gh"): return False
        si, cf = self._startupinfo_flags()
        try:
            subprocess.check_output(["gh","auth","status"], text=True, encoding="utf-8", errors="replace",
                                    stderr=subprocess.DEVNULL, startupinfo=si, creationflags=cf)
            return True
        except Exception:
            return False

    def _gh_login_with_token(self, token):
        if not self._exe_exists("gh"): return False
        if self._gh_auth_status_ok(): return True
        si, cf = self._startupinfo_flags()
        try:
            p = subprocess.Popen(["gh","auth","login","--with-token"],
                                 text=True, encoding="utf-8", errors="replace",
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 startupinfo=si, creationflags=cf)
            p.communicate(input=token+"\n", timeout=30)
            return p.returncode == 0
        except Exception as e:
            self.worker_queue.put(("log", f"ERROR gh auth login: {e}"))
            return False

    def _create_remote(self, repo):
        if not self._exe_exists("gh"): return False
        self.worker_queue.put(("log", f"Creando repo remoto: {repo} (public)…"))
        rc = self._run_cmd(["gh","repo","create", repo, "--public"], cwd=None)
        return rc == 0

    def _save_pat_in_credential_manager(self, username, token):
        if os.name != "nt":
            self.worker_queue.put(("log","INFO: Guardar token en Credential Manager solo disponible en Windows."))
            return False
        si, cf = self._startupinfo_flags()
        try:
            p = subprocess.Popen(["git","credential","approve"],
                                 text=True, encoding="utf-8", errors="replace",
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 startupinfo=si, creationflags=cf)
            blob = f"protocol=https\nhost=github.com\nusername={username}\npassword={token}\n\n"
            p.communicate(input=blob, timeout=10)
            ok = (p.returncode == 0)
            if ok: self.worker_queue.put(("log","Token guardado en Credential Manager."))
            else:  self.worker_queue.put(("log","No se pudo guardar el token en Credential Manager."))
            return ok
        except Exception as e:
            self.worker_queue.put(("log", f"ERROR guardando token: {e}"))
            return False

    # ---------- Pipeline principal ----------
    def _worker_pipeline(self, project_path, repo_name, commit_msg, create_readme):
        try:
            self.worker_queue.put(("stat","Verificando herramientas…"))
            if not self._exe_exists("git"):
                self.worker_queue.put(("log","ERROR: Git no está en PATH.")); self.worker_queue.put(("done",None)); return
            if not self._exe_exists("gh"):
                self.worker_queue.put(("log","ADVERTENCIA: GitHub CLI (gh) no está en PATH. Se intentará push, pero no se podrá crear el repo remoto automáticamente."))

            # leer preferencias de GUI
            git_name = self.git_user_name_var.get().strip()
            git_mail = self.git_user_email_var.get().strip()
            method   = self.auth_method_var.get().strip() or "gh"
            gh_user  = self.github_user_var.get().strip()
            pat_user = self.pat_user_var.get().strip() or "github"
            pat_token= self.pat_token_var.get().strip()
            save_pat = self.pat_save_var.get()

            # identidad git
            steps_identity = [
                (["git","config","user.name", git_name], "git config user.name"),
                (["git","config","user.email", git_mail], "git config user.email"),
                (["git","config","core.autocrlf","true"], "git config core.autocrlf"),
                (["git","config","core.filemode","false"], "git config core.filemode"),
                (["git","config","core.longpaths","true"], "git config core.longpaths"),
            ]

            # ¿Repo local?
            first_time = not self._is_git_repo(project_path)
            if first_time:
                self.worker_queue.put(("stat","Inicializando repo (primera vez)…"))
                init_steps = [
                    (["git","init"], "git init"),
                    (["git","branch","-M","main"], "git branch -M main"),
                    (["git","add","."], "git add ."),
                    (["git","commit","-m","Primer commit","--allow-empty"], "git commit (primer)"),
                ]
                all_steps = steps_identity + init_steps
                for args, label in all_steps:
                    rc = self._run_cmd(args, cwd=project_path)
                    if rc != 0:
                        if self._remove_index_lock_if_any(project_path):
                            rc2 = self._run_cmd(args, cwd=project_path)
                            if rc2 == 0: continue
                        self.worker_queue.put(("log", f"ERROR en paso: {label}")); self.worker_queue.put(("done",None)); return
            else:
                # Asegurar identidad siempre
                for args, label in steps_identity:
                    if self._run_cmd(args, cwd=project_path)!=0:
                        self.worker_queue.put(("log", f"ERROR en paso: {label}")); self.worker_queue.put(("done",None)); return
                self._run_cmd(["git","branch","-M","main"], cwd=project_path)

            # Construir remoto según método
            origin_url = self._build_origin(method, gh_user, repo_name)
            self._ensure_origin(project_path, origin_url)

            # Si PAT: guardar en Credential Manager (opcional) + loguear gh si hace falta para crear remoto
            if method == "https_pat" and pat_token:
                if save_pat: self._save_pat_in_credential_manager(pat_user, pat_token)
                if self._exe_exists("gh"): self._gh_login_with_token(pat_token)

            # Crear repo remoto si no existe
            if self._exe_exists("gh") and gh_user and repo_name and not self._remote_exists(gh_user, repo_name):
                if not self._create_remote(repo_name):
                    self.worker_queue.put(("log","ERROR: no se pudo crear el repo remoto.")); self.worker_queue.put(("done",None)); return
                origin_url = self._build_origin(method, gh_user, repo_name)
                self._ensure_origin(project_path, origin_url)

            # add / commit cambios
            rc = self._run_cmd(["git","add","."], cwd=project_path)
            if rc != 0:
                if self._remove_index_lock_if_any(project_path):
                    rc = self._run_cmd(["git","add","."], cwd=project_path)
                if rc != 0:
                    self.worker_queue.put(("log","ERROR en git add .")); self.worker_queue.put(("done",None)); return

            rc = self._run_cmd(["git","diff","--cached","--quiet"], cwd=project_path)
            if rc != 0:
                if self._run_cmd(["git","commit","-m", commit_msg], cwd=project_path)!=0:
                    self.worker_queue.put(("log","ERROR en commit.")); self.worker_queue.put(("done",None)); return
            else:
                self.worker_queue.put(("log","No hay cambios para commitear."))

            # push
            rc = self._run_cmd(["git","push","-u","origin","main"], cwd=project_path)
            if rc != 0:
                if self._exe_exists("gh") and gh_user and repo_name and not self._remote_exists(gh_user, repo_name):
                    if self._create_remote(repo_name):
                        self._ensure_origin(project_path, origin_url)
                        rc = self._run_cmd(["git","push","-u","origin","main"], cwd=project_path)
                if rc != 0:
                    self.worker_queue.put(("log","ERROR en push. Revisa remoto/credenciales.")); self.worker_queue.put(("done",None)); return

            # README opcional
            if self.cfg.get("create_readme_if_missing", True):
                readme_path = os.path.join(project_path, "README.md")
                if not os.path.exists(readme_path):
                    with open(readme_path,"w",encoding="utf-8") as f:
                        f.write(f"# {repo_name}\n\nProyecto {repo_name}.\n")
                    self.worker_queue.put(("log","README.md creado."))
                    self._run_cmd(["git","add","README.md"], cwd=project_path)
                    if self._run_cmd(["git","commit","-m","Add README"], cwd=project_path)==0:
                        self._run_cmd(["git","push"], cwd=project_path)

            self.worker_queue.put(("stat","Pipeline completado."))

        except Exception as e:
            self.worker_queue.put(("log", f"ERROR pipeline: {e}")); self.worker_queue.put(("log", traceback.format_exc()))
        finally:
            self.worker_queue.put(("done", None))

    # ---------- Lock / detect helpers ----------
    def _remove_index_lock_if_any(self, path):
        top = self._git_toplevel(path)
        if not top: return False
        lock = os.path.join(top, ".git", "index.lock")
        if os.path.exists(lock):
            try:
                os.remove(lock)
                self.worker_queue.put(("log", f"Se removió lock: {lock}"))
                return True
            except Exception as e:
                self.worker_queue.put(("log", f"ERROR eliminando lock {lock}: {e}"))
        return False

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

        self.running=True; self.btn_run.config(state="disabled"); self.btn_stop.config(state="normal")
        self._status("Ejecutando pipeline…")
        self._append_log(f"Iniciando pipeline en: {proj} (repo: {repo})")

        # NO contar durante el pipeline
        self._cancel_autoclose()

        t=threading.Thread(target=self._worker_pipeline, args=(proj,repo,self.commit_message_var.get().strip() or "Actualización automática", self.create_readme_var.get()), daemon=True)
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

    def _detect_github_user(self):
        try:
            si, cf = self._startupinfo_flags()
            out = subprocess.check_output(["gh","api","user","-q",".login"],
                                          text=True, encoding="utf-8", errors="replace",
                                          stderr=subprocess.DEVNULL, startupinfo=si, creationflags=cf)
            user = out.strip()
            if user: self.worker_queue.put(("log", f"Usuario GitHub: {user}"))
            return user
        except: return ""

    def on_close(self):
        try:
            self.cfg["window_geometry"]=self.geometry(); safe_write_json(CONFIG_PATH,self.cfg)
        except: pass
        log_line("Aplicación cerrada por el usuario."); self.destroy()

# ---------- Main ----------
if __name__=="__main__":
    try:
        if not os.path.exists(LOG_PATH): open(LOG_PATH,"w",encoding="utf-8").close()
        log_line("=== Lanzamiento de la aplicación ===")
    except Exception as e:
        print("No se pudo crear log.txt:", e)
    app = App(); app.mainloop()
