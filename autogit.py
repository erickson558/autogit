# -*- coding: utf-8 -*-
"""
Git Helper GUI – v0.0.5
Cambios:
- (Windows) Oculta ventanas de Git/CMD para todos los subprocess (CREATE_NO_WINDOW + STARTF_USESHOWWINDOW).
- Autocierre: se PAUSA durante el pipeline y el countdown inicia al terminar.
- Silencia salida de 'git rev-parse' (evita 'true' en log).
- Mantiene: GUI no bloqueante, config.json, log.txt UTF-8, statusbar con countdown a la derecha, menú y atajos, pipeline git/gh.
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
    "window_geometry": "1000x640+100+100",
    "autostart": False,
    "autoclose_enabled": False,
    "autoclose_seconds": 60,
    "status_text": "Listo.",
    "shortcuts_enabled": True,

    # Campos Git GUI
    "project_path": app_dir(),
    "repo_name": "",
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
        m_app.add_command(label="Ejecutar pipeline", underline=0,
                          accelerator="Ctrl+R", command=self._start_pipeline)
        m_app.add_command(label="Detener", underline=0,
                          accelerator="Ctrl+D", command=self._stop_pipeline)
        m_app.add_separator()
        m_app.add_command(label="Salir", underline=0,
                          accelerator="Ctrl+Q", command=self.on_close)

        m_help = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Ayuda", menu=m_help, underline=0)
        m_help.add_command(label="About", underline=0,
                           accelerator="F1", command=self._show_about)

    def _build_widgets(self):
        # Top bar
        top = ttk.Frame(self); top.pack(fill="x", padx=16, pady=12)
        ttk.Label(top, text=APP_NAME, font=("Segoe UI Semibold", 14)).pack(side="left")
        self.version_label = ttk.Label(top, text=f"Versión: {self.cfg.get('version', INITIAL_VERSION)}",
                                       font=("Segoe UI Semibold", 10))
        self.version_label.pack(side="right")

        # Body
        body = ttk.Frame(self); body.pack(fill="both", expand=True, padx=16, pady=8)

        # Línea A: Autostart / Autocerrar
        rowA = ttk.Frame(body); rowA.pack(fill="x", pady=(4,4))
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

        # Línea B: Ruta del proyecto
        rowB = ttk.Frame(body); rowB.pack(fill="x", pady=(8,4))
        ttk.Label(rowB, text="Ruta del proyecto:").pack(side="left")
        self.project_path_var = tk.StringVar(value=self.cfg.get("project_path", app_dir()))
        e_path = ttk.Entry(rowB, width=70, textvariable=self.project_path_var)
        e_path.pack(side="left", padx=6, fill="x", expand=True)
        e_path.bind("<FocusOut>", lambda e: self._on_project_path_change())
        e_path.bind("<Return>",   lambda e: self._on_project_path_change())
        ttk.Button(rowB, text="Examinar…", command=self._browse_folder).pack(side="left", padx=(6,0))

        # Línea C: Repo name (autodetect)
        rowC = ttk.Frame(body); rowC.pack(fill="x", pady=(4,4))
        ttk.Label(rowC, text="Nombre del repo (GitHub):").pack(side="left")
        self.repo_name_var = tk.StringVar(value=self.cfg.get("repo_name",""))
        e_repo = ttk.Entry(rowC, width=40, textvariable=self.repo_name_var)
        e_repo.pack(side="left", padx=6)
        e_repo.bind("<FocusOut>", lambda e: self._on_str_change("repo_name", self.repo_name_var.get()))
        e_repo.bind("<Return>",   lambda e: self._on_str_change("repo_name", self.repo_name_var.get()))
        ttk.Button(rowC, text="Autodetectar", command=self._autodetect_repo_name).pack(side="left", padx=(6,0))

        # Línea D: Commit message + README
        rowD = ttk.Frame(body); rowD.pack(fill="x", pady=(4,4))
        ttk.Label(rowD, text="Mensaje de commit:").pack(side="left")
        self.commit_message_var = tk.StringVar(value=self.cfg.get("commit_message","Actualización automática"))
        e_msg = ttk.Entry(rowD, width=60, textvariable=self.commit_message_var)
        e_msg.pack(side="left", padx=6, fill="x", expand=True)
        e_msg.bind("<KeyRelease>", lambda e: self._on_str_change("commit_message", self.commit_message_var.get()))
        self.create_readme_var = tk.BooleanVar(value=self.cfg.get("create_readme_if_missing", True))
        ttk.Checkbutton(rowD, text="Crear README.md si falta",
                        variable=self.create_readme_var,
                        command=lambda: self._on_bool_change("create_readme_if_missing", self.create_readme_var.get())
                        ).pack(side="left", padx=(10,0))

        # Línea E: Botones
        rowE = ttk.Frame(body); rowE.pack(fill="x", pady=(12,6))
        self.btn_run  = ttk.Button(rowE, text="Ejecutar pipeline (Ctrl+R)", command=self._start_pipeline)
        self.btn_stop = ttk.Button(rowE, text="Detener (Ctrl+D)", command=self._stop_pipeline, state="disabled")
        self.btn_exit = ttk.Button(rowE, text="Salir (Ctrl+Q)", command=self.on_close)
        self.btn_run.pack(side="left"); self.btn_stop.pack(side="left", padx=8); self.btn_exit.pack(side="right")

        # Log visual
        logf = ttk.Frame(body); logf.pack(fill="both", expand=True, pady=(8,8))
        self.txt_log = tk.Text(logf, height=14, bg="#0F1620", fg="#C9D1D9", insertbackground="#C9D1D9", relief="flat", wrap="word")
        self.txt_log.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(logf, orient="vertical", command=self.txt_log.yview); sb.pack(side="right", fill="y")
        self.txt_log.configure(yscrollcommand=sb.set)

        # Status bar
        status = tk.Frame(self, bg="#0A0E12", bd=1, relief="sunken", height=24)
        status.pack(side="bottom", fill="x"); status.pack_propagate(False)
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

    # ---------- Config change handlers ----------
    def _on_bool_change(self, key, value):
        self.cfg[key]=bool(value); safe_write_json(CONFIG_PATH,self.cfg); self._bump_on_config_change(f"{key}={value}")
        self._status(f"Guardado {key} = {value}")
        # si activas autoclose mientras hay pipeline corriendo, no disparamos countdown hasta que termine
        if key=="autoclose_enabled":
            if value and not self.running:
                self._schedule_autoclose()
            else:
                self._cancel_autoclose()

    def _on_int_change(self, key, raw):
        try:
            v=int(str(raw).strip()); v=1 if v<1 else (86400 if v>86400 else v)
        except: v=DEFAULT_CONFIG.get(key,60)
        self.cfg[key]=v; safe_write_json(CONFIG_PATH,self.cfg); self._bump_on_config_change(f"{key}={v}")
        self._status(f"Guardado {key} = {v}")
        if key=="autoclose_seconds" and self.autoclose_var.get() and not self.running: self._schedule_autoclose()

    def _on_str_change(self, key, value):
        self.cfg[key]=value; safe_write_json(CONFIG_PATH,self.cfg); self._bump_on_config_change(f"{key}=len{len(value)}")
        self._status(f"Guardado {key}")

    def _on_project_path_change(self):
        self._on_str_change("project_path", self.project_path_var.get())
        if not self.repo_name_var.get(): self._autodetect_repo_name()

    def _browse_folder(self):
        path = filedialog.askdirectory(initialdir=self.project_path_var.get() or app_dir(), title="Selecciona la carpeta del proyecto")
        if path:
            self.project_path_var.set(path); self._on_project_path_change()

    def _autodetect_repo_name(self):
        p = self.project_path_var.get().strip() or app_dir()
        repo = os.path.basename(os.path.normpath(p)) or ""
        if repo:
            self.repo_name_var.set(repo); self._on_str_change("repo_name", repo)
            self._status(f"Repo autodetectado: {repo}")

    def _bump_on_config_change(self, reason=""):
        old=self.cfg.get("version",INITIAL_VERSION); new=bump_version(old)
        self.cfg["version"]=new; safe_write_json(CONFIG_PATH,self.cfg)
        # nota: no forzamos bump visual aquí para no “parpadear” la UI; opcional:
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
        self._tick_countdown()

    def _cancel_autoclose(self):
        if self.countdown_job is not None:
            try: self.after_cancel(self.countdown_job)
            except: pass
            self.countdown_job = None
        self.countdown_var.set("")

    def _tick_countdown(self):
        if not self.autoclose_var.get():
            self._cancel_autoclose(); return
        self.countdown_var.set(f"Auto-cierre: {self.autoclose_remaining} s")
        if self.autoclose_remaining <= 0:
            self.countdown_var.set("Auto-cierre: 0 s")
            self.on_close(); return
        self.autoclose_remaining -= 1
        self.countdown_job = self.after(1000, self._tick_countdown)

    # ---------- Pipeline control ----------
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

        # IMPORTANTE: NO iniciar countdown durante el pipeline
        self._cancel_autoclose()

        t=threading.Thread(target=self._worker_pipeline, args=(proj,repo,self.commit_message_var.get().strip() or "Actualización automática", self.create_readme_var.get()), daemon=True)
        t.start()

    def _stop_pipeline(self):
        if not self.running: self._status("No hay proceso en ejecución."); return
        self.running=False; self._append_log("Solicitud de detener recibida… (se detiene al finalizar el paso actual)")

    def _poll_worker_queue(self):
        try:
            while True:
                kind, payload = self.worker_queue.get_nowait()
                if kind=="log":    self._append_log(payload)
                elif kind=="stat": self._status(payload)
                elif kind=="done":
                    self.running=False; self.btn_run.config(state="normal"); self.btn_stop.config(state="disabled")
                    # countdown SOLO cuando termina (si está activado)
                    if self.autoclose_var.get():
                        self._schedule_autoclose()
        except queue.Empty:
            pass
        self.after(120, self._poll_worker_queue)

    # ---------- Helpers de subprocess (Windows: sin ventana) ----------
    def _startupinfo_flags(self):
        si = None
        cf = 0
        if os.name == "nt":
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            try:
                cf = subprocess.CREATE_NO_WINDOW  # oculta ventana de consola
            except AttributeError:
                cf = 0
        return si, cf

    def _exe_exists(self, name):
        for p in os.environ.get("PATH","").split(os.pathsep):
            full=os.path.join(p, name + (".exe" if os.name=="nt" else ""))
            if os.path.isfile(full): return True
        return False

    def _run_cmd(self, args, cwd, stream=True):
        """Ejecuta comando ocultando ventana en Windows y capturando UTF-8."""
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
        """check_output con ventana oculta en Windows y UTF-8."""
        si, cf = self._startupinfo_flags()
        return subprocess.check_output(
            args, cwd=cwd, text=True, encoding="utf-8", errors="replace",
            stderr=subprocess.DEVNULL, startupinfo=si, creationflags=cf
        )

    def _is_git_repo(self, path):
        # No logueamos la salida; solo evaluamos returncode
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

    def _remote_url(self, path):
        try:
            out = self._run_check_output(["git","remote","get-url","origin"], cwd=path).strip()
            return out
        except: return ""

    def _ensure_origin(self, path, user, repo):
        expected = f"https://github.com/{user}/{repo}.git"
        current  = self._remote_url(path)
        if not current:
            self.worker_queue.put(("log", f"Agregando origin -> {expected}"))
            self._run_cmd(["git","remote","add","origin", expected], cwd=path)
        elif current.lower()!=expected.lower():
            self.worker_queue.put(("log", f"Actualizando origin: {current} -> {expected}"))
            self._run_cmd(["git","remote","set-url","origin", expected], cwd=path)

    # ---------- Pipeline worker ----------
    def _worker_pipeline(self, project_path, repo_name, commit_msg, create_readme):
        try:
            self.worker_queue.put(("stat","Verificando herramientas…"))
            if not self._exe_exists("git"):
                self.worker_queue.put(("log","ERROR: Git no está en PATH.")); self.worker_queue.put(("done",None)); return
            if not self._exe_exists("gh"):
                self.worker_queue.put(("log","ERROR: GitHub CLI (gh) no está en PATH. Ejecuta 'gh auth login' previamente.")); self.worker_queue.put(("done",None)); return

            user = self._detect_github_user()
            if not user:
                self.worker_queue.put(("log","ADVERTENCIA: no se pudo detectar el usuario de GitHub vía 'gh'; se asume el dueño por el remoto al crear."))

            first_time = not self._is_git_repo(project_path)
            if first_time:
                self.worker_queue.put(("stat","Inicializando repo (primera vez)…"))
                steps = [
                    (["git","init"], "git init"),
                    (["git","config","user.name","erickson558"], "git config user.name"),
                    (["git","config","user.email","erickson558@hotmail.com"], "git config user.email"),
                    (["git","config","core.autocrlf","true"], "git config core.autocrlf"),
                    (["git","config","core.filemode","false"], "git config core.filemode"),
                    (["git","config","core.longpaths","true"], "git config core.longpaths"),
                    (["git","branch","-M","main"], "git branch -M main"),
                    (["git","add","."], "git add ."),
                    (["git","commit","-m","Primer commit","--allow-empty"], "git commit (primer)"),
                ]
                for args, label in steps:
                    if self._run_cmd(args, cwd=project_path)!=0:
                        self.worker_queue.put(("log", f"ERROR en paso: {label}")); self.worker_queue.put(("done",None)); return

                self.worker_queue.put(("log", f"Creando repo remoto: {repo_name} (public)…"))
                rc = self._run_cmd(["gh","repo","create",repo_name,"--public","--source",".","--remote","origin"], cwd=project_path)
                if rc!=0:
                    self.worker_queue.put(("log","No se pudo crear con '--source'; intentando creación simple…"))
                    rc2 = self._run_cmd(["gh","repo","create",repo_name,"--public"], cwd=project_path)
                    if rc2==0:
                        if user: self._ensure_origin(project_path, user, repo_name)
                    else:
                        self.worker_queue.put(("log","ERROR: no se pudo crear el repo remoto.")); self.worker_queue.put(("done",None)); return

                if self._run_cmd(["git","push","-u","origin","main"], cwd=project_path)!=0:
                    self.worker_queue.put(("log","ERROR en push inicial. Revisa 'gh auth login' o permisos.")); self.worker_queue.put(("done",None)); return

                if create_readme:
                    readme_path = os.path.join(project_path, "README.md")
                    if not os.path.exists(readme_path):
                        with open(readme_path,"w",encoding="utf-8") as f:
                            f.write(f"# {repo_name}\n\nProyecto {repo_name}.\n")
                        self.worker_queue.put(("log","README.md creado."))
                    self._run_cmd(["git","add","README.md"], cwd=project_path)
                    rc = self._run_cmd(["git","commit","-m","Add README"], cwd=project_path)
                    if rc==0:
                        self._run_cmd(["git","push"], cwd=project_path)
                    else:
                        self.worker_queue.put(("log","INFO: nada que commitear para README."))

                self.worker_queue.put(("stat","Pipeline inicial completado."))

            else:
                self.worker_queue.put(("stat","Repo existente: realizando commit/push…"))
                self._run_cmd(["git","branch","-M","main"], cwd=project_path)
                if user: self._ensure_origin(project_path, user, repo_name)

                self._run_cmd(["git","add","."], cwd=project_path)
                # ¿hay algo staged?
                rc = self._run_cmd(["git","diff","--cached","--quiet"], cwd=project_path)
                if rc!=0:
                    if self._run_cmd(["git","commit","-m", commit_msg], cwd=project_path)!=0:
                        self.worker_queue.put(("log","ERROR en commit.")); self.worker_queue.put(("done",None)); return
                else:
                    self.worker_queue.put(("log","No hay cambios para commitear."))

                if self._run_cmd(["git","push","-u","origin","main"], cwd=project_path)!=0:
                    self.worker_queue.put(("log","ERROR en push. Revisa remoto/credenciales.")); self.worker_queue.put(("done",None)); return

                self.worker_queue.put(("stat","Commit y push completados."))

        except Exception as e:
            self.worker_queue.put(("log", f"ERROR pipeline: {e}")); self.worker_queue.put(("log", traceback.format_exc()))
        finally:
            self.worker_queue.put(("done", None))

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

    # ---------- Cierre ----------
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
