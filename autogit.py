#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AutoGit – Subir carpeta actual a GitHub con creación remota del repo.
Versión: v0.2.0
Compatibilidad: Windows 10/11, Python 3.8+ (funciona en Linux/Mac con ajustes mínimos).
"""

import os, sys, json, base64, queue, shlex, threading, subprocess
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox

APP_VERSION = "0.2.0"
CONFIG_FILE = "config_autogit.json"

# ---------- Helpers para codificar/decodificar PAT ----------
def encode_token(tok):
    try:
        return base64.b64encode(tok.encode("utf-8")).decode("utf-8")
    except Exception:
        return tok

def decode_token(tok):
    try:
        return base64.b64decode(tok.encode("utf-8")).decode("utf-8")
    except Exception:
        return tok

# ---------- Ejecutar comandos ----------
def _startupinfo_flags():
    si = None; cf = 0
    if os.name == "nt":
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0
        cf = 0x08000000
    return si, cf

def run_cmd(args, cwd=None, timeout=None, input_text=None):
    si, cf = _startupinfo_flags()
    p = subprocess.Popen(args, cwd=cwd,
        stdin=subprocess.PIPE if input_text else None,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace",
        startupinfo=si, creationflags=cf)
    out, _ = p.communicate(input=input_text, timeout=timeout)
    return p.returncode, out

# ---------- Clase principal ----------
class AutoGit:
    def __init__(self, ui, logq):
        self.ui = ui; self.logq = logq

    def exe_exists(self, name):
        rc, _ = run_cmd(["where" if os.name=="nt" else "which", name])
        return rc == 0

    def gh_auth_status_ok(self):
        if not self.exe_exists("gh"): return False
        rc, out = run_cmd(["gh", "auth", "status"])
        return rc == 0 and "Logged in" in (out or "")

    def gh_login_with_token(self, token):
        if not self.exe_exists("gh"): return False
        self.log("🔐 gh auth login con PAT…")
        rc, out = run_cmd(["gh","auth","login","--with-token"], input_text=token+"\n")
        return rc == 0 and self.gh_auth_status_ok()

    def gh_remote_exists(self, user, repo):
        rc, _ = run_cmd(["gh","repo","view",f"{user}/{repo}"])
        return rc == 0

    def gh_create_remote(self, user, repo, vis):
        rc, out = run_cmd(["gh","repo","create",f"{user}/{repo}","--"+vis])
        if rc!=0:
            self.log("❌ Error creando repo remoto: "+(out or ""))
            return False
        self.log("✅ Repo remoto creado.")
        return True

    def git(self, args, cwd): return run_cmd(["git"]+args, cwd=cwd)

    # ---------- Pipeline principal ----------
    def pipeline(self, cfg):
        try:
            self._inner(cfg)
        except Exception as e:
            self.log(f"💥 ERROR: {e}")
        finally:
            self.ui.after(0, self.ui.set_running, False)

    def _inner(self, cfg):
        proj = cfg["project_dir"]
        user = cfg["gh_user"].strip()
        repo = cfg["repo_name"].strip()
        vis = cfg["visibility"]

        token = cfg.get("pat_token","").strip()
        if not token and cfg.get("pat_token_encoded"):
            token = decode_token(cfg["pat_token_encoded"])

        self.log(f"▶️ Iniciando pipeline en {proj} → {repo}")

        if cfg["auth_method"]=="https_pat" and token:
            if not self.gh_auth_status_ok():
                if not self.gh_login_with_token(token):
                    self.log("❌ No se pudo autenticar con PAT."); return
        else:
            if not self.gh_auth_status_ok() and token:
                self.gh_login_with_token(token)

        # git init
        if not os.path.isdir(os.path.join(proj,".git")):
            self.git(["init"], cwd=proj)
            self.git(["checkout","-B","main"], cwd=proj)

        # add/commit
        self.git(["add","-A"], cwd=proj)
        self.git(["commit","-m",cfg["commit_message"]], cwd=proj)

        if not self.gh_remote_exists(user, repo):
            if not self.gh_create_remote(user, repo, vis): return
        rc,out=self.git(["remote"],cwd=proj)
        if "origin" not in (out or ""):
            self.git(["remote","add","origin",f"https://github.com/{user}/{repo}.git"],cwd=proj)
        rc,out=self.git(["push","-u","origin","main"],cwd=proj)
        if rc!=0: self.log("❌ git push: "+(out or "")); return
        self.log("✅ Push completado.")

    def log(self,msg): self.logq.put(msg)

# ---------- GUI ----------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"AutoGit v{APP_VERSION}"); self.geometry("900x650")
        self.logq=queue.Queue(); self.autogit=AutoGit(self,self.logq)
        self._load_cfg(); self._build()
        self.after(100,self._poll)

    def _load_cfg(self):
        self.cfg={}
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE,"r") as f: self.cfg=json.load(f)
            except: self.cfg={}
        for k,v in {"gh_user":"erickson558","repo_name":"","visibility":"public",
                    "auth_method":"gh","pat_token_encoded":"",
                    "project_dir":os.getcwd(),"commit_message":"Auto commit"}.items():
            self.cfg.setdefault(k,v)

    def _save_cfg(self):
        tok=self.var_pat.get().strip()
        if tok: self.cfg["pat_token_encoded"]=encode_token(tok)
        self.cfg.update({
            "gh_user":self.var_user.get(),
            "repo_name":self.var_repo.get(),
            "visibility":self.var_vis.get(),
            "auth_method":self.var_auth.get(),
            "project_dir":self.var_proj.get(),
            "commit_message":self.var_commit.get()
        })
        with open(CONFIG_FILE,"w") as f: json.dump(self.cfg,f,indent=2)

    def _build(self):
        pad=6
        f=ttk.Frame(self); f.pack(fill="x",pady=pad)
        ttk.Label(f,text="Usuario GH").pack(side="left")
        self.var_user=tk.StringVar(value=self.cfg["gh_user"])
        ttk.Entry(f,textvariable=self.var_user,width=20).pack(side="left",padx=pad)
        ttk.Label(f,text="Repo").pack(side="left")
        self.var_repo=tk.StringVar(value=self.cfg["repo_name"])
        ttk.Entry(f,textvariable=self.var_repo,width=20).pack(side="left",padx=pad)
        ttk.Label(f,text="Visibilidad").pack(side="left")
        self.var_vis=tk.StringVar(value=self.cfg["visibility"])
        ttk.Combobox(f,textvariable=self.var_vis,values=["public","private"],width=8).pack(side="left",padx=pad)

        f2=ttk.Frame(self); f2.pack(fill="x",pady=pad)
        ttk.Label(f2,text="Auth").pack(side="left")
        self.var_auth=tk.StringVar(value=self.cfg["auth_method"])
        ttk.Combobox(f2,textvariable=self.var_auth,values=["gh","https_pat"],width=10).pack(side="left")
        ttk.Label(f2,text="PAT").pack(side="left")
        self.var_pat=tk.StringVar()
        if self.cfg.get("pat_token_encoded"):
            self.var_pat.set("<guardado>")
        ttk.Entry(f2,textvariable=self.var_pat,width=40,show="•").pack(side="left",padx=pad)

        f3=ttk.Frame(self); f3.pack(fill="x",pady=pad)
        ttk.Label(f3,text="Ruta proyecto").pack(side="left")
        self.var_proj=tk.StringVar(value=self.cfg["project_dir"])
        ttk.Entry(f3,textvariable=self.var_proj,width=50).pack(side="left",padx=pad)
        ttk.Button(f3,text="Examinar",command=self._browse).pack(side="left")

        f4=ttk.Frame(self); f4.pack(fill="x",pady=pad)
        ttk.Label(f4,text="Commit msg").pack(side="left")
        self.var_commit=tk.StringVar(value=self.cfg["commit_message"])
        ttk.Entry(f4,textvariable=self.var_commit,width=50).pack(side="left",padx=pad)

        fb=ttk.Frame(self); fb.pack(fill="x",pady=pad)
        self.btn_run=ttk.Button(fb,text="Ejecutar pipeline",command=self._run)
        self.btn_run.pack(side="left"); ttk.Button(fb,text="Salir",command=self.destroy).pack(side="right")

        lf=ttk.LabelFrame(self,text="Log"); lf.pack(fill="both",expand=True,padx=pad,pady=pad)
        self.txt=scrolledtext.ScrolledText(lf,state="disabled"); self.txt.pack(fill="both",expand=True)

    def _browse(self):
        d=filedialog.askdirectory(initialdir=self.var_proj.get() or os.getcwd())
        if d: self.var_proj.set(d)

    def _run(self):
        self._save_cfg()
        self.btn_run.configure(state="disabled")
        cfg=self.cfg.copy(); cfg["pat_token"]=self.var_pat.get() if self.var_pat.get()!="<guardado>" else ""
        t=threading.Thread(target=self.autogit.pipeline,args=(cfg,),daemon=True)
        t.start()

    def _poll(self):
        try:
            while True: self._append(self.logq.get_nowait())
        except queue.Empty: pass
        self.after(100,self._poll)

    def _append(self,msg):
        self.txt.configure(state="normal"); self.txt.insert("end",msg+"\n"); self.txt.see("end"); self.txt.configure(state="disabled")

    def set_running(self,flag): self.btn_run.configure(state="disabled" if flag else "normal")

if __name__=="__main__":
    App().mainloop()
