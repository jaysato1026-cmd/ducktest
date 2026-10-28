"""PHPtoSHELL 防禦程式。No network listener or web UI."""
import argparse
import csv
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import queue
import socket
import shutil
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog

from watch import Tracker, Backend, normalize
from diagnostics import ToolResult, tool_status, nmap_inventory, tshark_interfaces, iperf3_probe, local_connections, http_probe
from php_audit import LogTailMonitor, audit_php_config, audit_log_file
from ip_intel import classify, parse_list_file
from runtime_inventory import runtime_inventory
from health import append_event, health_snapshot

AUTHOR = '王宥傑'
VERSION = '2026.10.28'
# Windows 11 Fluent-like palette: light neutral canvas, white surfaces, restrained accent.
COLORS = dict(bg='#f4f7fb', panel='#ffffff', border='#dbe4ef', text='#182b45',
              muted='#596d85', blue='#2458d3', green='#137b5b', amber='#986100',
              red='#bd3546', navy='#142b4d', pale='#eaf1fc')


def new_policy():
    return dict(version=1, port=8080, inventory_approved=False, target_computer='', allowed_sources=[], geo_sources=[], object_ips=[])


class DemoBackend:
    """In-memory UI fixture. Never executes PowerShell or reads host connections."""
    def __init__(self): self.blocked = set()
    def call(self, operation, address=None):
        if operation == 'Check': return {'ready': True}
        if operation == 'Blocks': return [{'Addresses': [s], 'Enabled': 'True'} for s in sorted(self.blocked)]
        if operation == 'Poll':
            return [dict(RemoteAddress=s, LocalAddress='192.0.2.10', OwningProcess=1000)
                    for s in ['192.0.2.25', '192.0.2.31', '203.0.113.8', '203.0.113.50'] if s not in self.blocked]
        if operation == 'Block': self.blocked.add(address); return {'blocked': True, 'tcp_close_proven': False}
        if operation == 'Unblock': self.blocked.discard(address); return {'unblocked': True}
        raise ValueError(operation)


class App:
    def __init__(self, root, data_dir, demo=False):
        self.root, self.data_dir, self.demo = root, data_dir, demo
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.policy_path = data_dir / 'policy.json'
        if not self.policy_path.exists():
            companion = Path(sys.executable if getattr(sys, 'frozen', False) else __file__).with_name('policy.local.json')
            if companion.exists() and not demo:
                shutil.copyfile(companion, self.policy_path)
            else:
                self.policy_path.write_text(json.dumps(new_policy(), indent=2), encoding='utf-8')
        self.policy = json.loads(self.policy_path.read_text(encoding='utf-8-sig'))
        self.policy.setdefault('geo_sources', [])
        self.policy.setdefault('object_ips', [])
        if demo:
            self.policy = new_policy(); self.policy['allowed_sources'] = ['192.0.2.25/32', '192.0.2.31/32']
        self.tracker = Tracker(self.policy['allowed_sources'] or ['127.0.0.0/8'])
        self.backend = DemoBackend() if demo else Backend(self.policy_path)
        self.jobs, self.results = queue.Queue(), queue.Queue()
        self.rows, self.blocks, self.pending = {}, set(), set()
        self.service_rows, self.connection_rows = [], []
        self.auto, self.ready, self.paused, self.poll_pending = False, False, False, False
        self.diag_busy = False
        self.php_executable = None
        self.runtime_php_paths = []
        self.logwatch_stop = None
        self.closed = False
        self.started_at = dt.datetime.now(dt.timezone.utc)
        self.last_poll_at = None
        self.last_firewall_check_at = None
        self.error_count = 0
        self._layout()
        threading.Thread(target=self._worker, daemon=True).start()
        threading.Thread(target=self._snapshot_worker, daemon=True).start()
        self.jobs.put(('check', None, None)); self.jobs.put(('blocks', None, None))
        self.root.after(100, self._drain)
        self.root.after(250, self._poll)
        self.root.after(1000, self._tick)
        self.root.protocol('WM_DELETE_WINDOW', self._close)
        self.root.bind('<F5>', lambda _event: self._poll(schedule=False))
        self.root.bind('<Control-l>', self._open_logs)
        self.notebook.enable_traversal()
        self.log('已啟動展示模式；不讀取或變更主機防火牆。' if demo else '已啟動手動模式；自動停止預設關閉。')

    def _layout(self):
        c = COLORS; root = self.root
        root.title('PHPtoSHELL 防禦程式｜來源防禦控制台' + (' [展示模式]' if self.demo else ''))
        root.geometry('1240x820'); root.minsize(900, 600); root.configure(bg=c['bg'])
        self.style = ttk.Style(root); self.style.theme_use('clam')
        self.style.configure('.', font=('Microsoft JhengHei UI', 10), background=c['bg'], foreground=c['text'])
        self.style.configure('TFrame', background=c['bg'])
        self.style.configure('Card.TFrame', background=c['panel'])
        self.style.configure('TLabel', background=c['bg'], foreground=c['text'])
        self.style.configure('Muted.TLabel', foreground=c['muted'])
        self.style.configure('Card.TLabel', background=c['panel'])
        self.style.configure('TButton', padding=(14, 9), background='#ffffff', foreground=c['text'], borderwidth=1, relief='flat')
        self.style.map('TButton', background=[('active', c['pale'])], foreground=[('disabled', '#8b9bab')])
        self.style.configure('Primary.TButton', background=c['blue'], foreground='white')
        self.style.map('Primary.TButton', background=[('active', '#1746b7')])
        self.style.configure('Danger.TButton', background='#fff0f2', foreground=c['red'])
        self.style.configure('Treeview', background='#ffffff', fieldbackground='#ffffff', foreground=c['text'],
                             rowheight=32, borderwidth=0)
        self.style.configure('Treeview.Heading', background='#eaf0f7', foreground=c['text'], padding=9,
                             font=('Microsoft JhengHei UI', 10, 'bold'))
        self.style.map('Treeview', background=[('selected', '#dbeeff')], foreground=[('selected', '#1f1f1f')])
        self.style.configure('TNotebook', background=c['bg'], borderwidth=0)
        self.style.configure('TNotebook.Tab', padding=(18, 10), background='#e7edf5', foreground=c['muted'])
        self.style.map('TNotebook.Tab', background=[('selected', '#ffffff')], foreground=[('selected', c['blue'])])
        viewport = ttk.Frame(root); viewport.pack(fill='both', expand=True)
        canvas = tk.Canvas(viewport, background=c['bg'], highlightthickness=0, borderwidth=0)
        self.page_canvas = canvas
        page_scroll = ttk.Scrollbar(viewport, orient='vertical', command=canvas.yview)
        canvas.configure(yscrollcommand=page_scroll.set)
        canvas.pack(side='left', fill='both', expand=True)
        page_scroll.pack(side='right', fill='y')
        outer = ttk.Frame(canvas, padding=16)
        page = canvas.create_window((0, 0), window=outer, anchor='nw')
        outer.bind('<Configure>', lambda _event: canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.bind('<Configure>', lambda event: canvas.itemconfigure(page, width=event.width))
        root.bind_all('<MouseWheel>', self._scroll_page, add='+')
        hero = tk.Frame(outer, bg=c['navy'], padx=22, pady=17)
        hero.pack(fill='x', pady=(0, 12))
        tk.Label(hero, text='PHPtoSHELL  /  SECURITY OPERATIONS', bg=c['navy'], fg='#a5c2f2',
                 font=('Segoe UI', 10, 'bold')).pack(anchor='w')
        hero_row = tk.Frame(hero, bg=c['navy']); hero_row.pack(fill='x', pady=(6, 0))
        tk.Label(hero_row, text='來源防禦控制台', bg=c['navy'], fg='white',
                 font=('Microsoft JhengHei UI', 23, 'bold')).pack(side='left')
        tk.Label(hero_row, text=('展示模式' if self.demo else 'TCP 8080 · 本機監看'),
                 bg='#315987', fg='white', padx=12, pady=5,
                 font=('Microsoft JhengHei UI', 10, 'bold')).pack(side='right')
        tk.Label(hero, text='辨識未知來源  ·  保留 180 秒核對時間  ·  由操作人員決定是否封鎖',
                 bg=c['navy'], fg='#d8e5f7', font=('Microsoft JhengHei UI', 10)).pack(anchor='w', pady=(6, 0))
        tk.Label(hero, text='v'+VERSION+'   ·   '+AUTHOR, bg=c['navy'], fg='#9eb4d1',
                 font=('Microsoft JhengHei UI', 9)).pack(anchor='e')
        cards = ttk.Frame(outer); cards.pack(fill='x')
        self.card_vars = {}
        for index, (key, title, initial, accent) in enumerate([('mode', '控制模式', '手動', c['blue']),
                                                               ('unknown', '待核對來源', '0', c['amber']),
                                                               ('blocked', '已啟用封鎖規則', '0', c['red']),
                                                               ('update', '上次連線取樣', '等待資料', c['green'])]):
            cards.columnconfigure(index, weight=1)
            card = tk.Frame(cards, bg=c['panel'], highlightbackground=c['border'], highlightthickness=1)
            card.grid(row=0, column=index, sticky='ew', padx=(0, 10 if index < 3 else 0))
            tk.Frame(card, bg=accent, height=4).pack(fill='x')
            content = tk.Frame(card, bg=c['panel'], padx=14, pady=11); content.pack(fill='both')
            tk.Label(content, text=title, bg=c['panel'], fg=c['muted'],
                     font=('Microsoft JhengHei UI', 10)).pack(anchor='w')
            var = tk.StringVar(value=initial); self.card_vars[key] = var
            tk.Label(content, textvariable=var, bg=c['panel'], fg=c['text'],
                     font=('Microsoft JhengHei UI', 18, 'bold')).pack(anchor='w', pady=(6, 0))
        controls = ttk.Frame(outer); controls.pack(fill='x', pady=10)
        self.auto_button = ttk.Button(controls, text='自動停止：關閉', command=self._toggle_auto, style='Primary.TButton')
        self.auto_button.pack(side='left')
        self.firewall_button = ttk.Button(controls, text='檢查 Windows Firewall', command=self._firewall_check)
        self.firewall_button.pack(side='left', padx=8)
        self.pause_button = ttk.Button(controls, text='暫停觀察', command=self._toggle_pause); self.pause_button.pack(side='left', padx=8)
        ttk.Button(controls, text='立即更新', command=lambda: self._poll(schedule=False)).pack(side='left')
        self.status = tk.StringVar(value='正在確認防火牆與執行權限…')
        ttk.Label(outer, textvariable=self.status, style='Muted.TLabel', wraplength=1000).pack(anchor='w', pady=(0, 10))
        dashboard = tk.Frame(outer, bg=c['panel'], highlightbackground=c['border'], highlightthickness=1,
                             padx=15, pady=10)
        dashboard.pack(fill='x', pady=(0, 10))
        left = tk.Frame(dashboard, bg=c['panel']); left.pack(side='left', fill='x', expand=True)
        tk.Label(left, text='防護範圍  /  TCP 8080', bg=c['panel'], fg=c['text'],
                 font=('Microsoft JhengHei UI', 11, 'bold')).pack(anchor='w')
        tk.Label(left, text='來源與服務埠盤點；HTTP 請求內容仍需前端防護。', bg=c['panel'],
                 fg=c['muted'], font=('Microsoft JhengHei UI', 9)).pack(anchor='w', pady=(3, 0))
        self.dashboard_vars = {'health': tk.StringVar(value='待檢查'), 'detail': tk.StringVar(value='尚未完成第一次取樣')}
        tk.Label(dashboard, textvariable=self.dashboard_vars['health'], bg=c['pale'], fg=c['blue'],
                 font=('Microsoft JhengHei UI', 10, 'bold'), padx=12, pady=6).pack(side='right')
        tk.Label(left, textvariable=self.dashboard_vars['detail'], bg=c['panel'], fg=c['muted'],
                 font=('Microsoft JhengHei UI', 9)).pack(anchor='w', pady=(5, 0))
        notebook = ttk.Notebook(outer); notebook.pack(fill='both', expand=True)
        self.notebook = notebook
        dash_tab = ttk.Frame(notebook, padding=8); notebook.add(dash_tab, text='Dashboard')
        service_area = ttk.Frame(dash_tab); service_area.pack(fill='x')
        self.service_table = ttk.Treeview(service_area, columns=('service','port','state','note'), show='headings', height=5)
        for name, title, width in zip(('service','port','state','note'), ('服務','埠號','狀態','說明'), (220, 100, 140, 600)):
            self.service_table.heading(name, text=title); self.service_table.column(name, width=width, stretch=name == 'note')
        self.service_table.tag_configure('up', foreground=COLORS['green']); self.service_table.tag_configure('down', foreground=COLORS['muted'])
        self.service_table.pack(side='left', fill='x', expand=True)
        service_scroll = ttk.Scrollbar(service_area, orient='vertical', command=self.service_table.yview)
        self.service_table.configure(yscrollcommand=service_scroll.set); service_scroll.pack(side='right', fill='y')
        ttk.Label(dash_tab, text='目前連線對象', font=('Segoe UI', 11, 'bold')).pack(anchor='w', pady=(8, 4))
        connection_area = ttk.Frame(dash_tab); connection_area.pack(fill='both', expand=True)
        self.connection_table = ttk.Treeview(connection_area, columns=('remote','service','port','state','pid'), show='headings', height=4)
        for name, title, width in zip(('remote','service','port','state','pid'), ('遠端 IP','服務','本機埠','狀態','PID'), (230, 180, 100, 150, 100)):
            self.connection_table.heading(name, text=title); self.connection_table.column(name, width=width, stretch=name == 'remote')
        self.connection_table.pack(side='left', fill='both', expand=True)
        connection_scroll = ttk.Scrollbar(connection_area, orient='vertical', command=self.connection_table.yview)
        self.connection_table.configure(yscrollcommand=connection_scroll.set); connection_scroll.pack(side='right', fill='y')
        ttk.Label(dash_tab, text=('展示模式：以下為範例資料。' if self.demo else 'Dashboard 只讀取本機狀態；封鎖操作集中在「來源連線」頁籤。'), style='Muted.TLabel').pack(anchor='w', pady=(6, 0))
        tab = ttk.Frame(notebook, padding=(0, 12)); notebook.add(tab, text='來源連線')
        actions = ttk.Frame(tab); actions.pack(fill='x', padx=8, pady=(0, 8))
        self.block_button = ttk.Button(actions, text='停止選取來源連入', command=self._manual_block, style='Danger.TButton')
        self.block_button.pack(side='left')
        ttk.Button(actions, text='解除選取來源封鎖', command=self._unblock).pack(side='left', padx=8)
        ttk.Button(actions, text='加入白名單', command=self._allow_selected).pack(side='left')
        ttk.Button(actions, text='反向 DNS 偵測', command=self._reverse_lookup).pack(side='left', padx=8)
        ttk.Button(actions, text='比對 IP 情資', command=self._show_ip_intel).pack(side='left')
        ttk.Label(tab, text='每 5 秒取樣目前連線；短暫 HTTP 請求可能不會被標記。關閉程式不會自動解除既有封鎖。', style='Muted.TLabel').pack(anchor='w', padx=8, pady=(0, 8))
        table_area = ttk.Frame(tab); table_area.pack(fill='both', expand=True)
        cols = ('source', 'state', 'count', 'first', 'timer', 'action')
        self.table = ttk.Treeview(table_area, columns=cols, show='headings', selectmode='browse')
        for name, title, width in zip(cols, ['來源 IP', '狀態', '連線數', '首次標記', '自動停止倒數', '處理結果'], [225, 135, 75, 120, 130, 300]):
            self.table.heading(name, text=title); self.table.column(name, width=width, minwidth=65, stretch=name in ('source','action'))
        self.table.tag_configure('trusted', foreground=c['green'])
        self.table.tag_configure('unknown', foreground=c['amber'])
        self.table.tag_configure('blocked', foreground=c['red'])
        scroll = ttk.Scrollbar(table_area, orient='vertical', command=self.table.yview); self.table.configure(yscrollcommand=scroll.set)
        self.table.pack(side='left', fill='both', expand=True); scroll.pack(side='right', fill='y')
        self.empty_state = tk.Frame(table_area, bg=c['panel'])
        self.empty_state.place(relx=0, rely=0, relwidth=1, relheight=1)
        tk.Label(self.empty_state, text='目前沒有可處理的來源連線', bg=c['panel'], fg=c['text'],
                 font=('Microsoft JhengHei UI', 14, 'bold')).pack(pady=(72, 6))
        self.empty_detail = tk.Label(self.empty_state, text='請先按「立即更新」；若仍無資料，代表目前沒有連入 TCP 8080 的來源。',
                                     bg=c['panel'], fg=c['muted'], font=('Microsoft JhengHei UI', 10))
        self.empty_detail.pack()
        menu = tk.Menu(root, tearoff=False, bg=c['panel'], fg=c['text'])
        menu.add_command(label='停止此來源連入 8080', command=self._manual_block)
        menu.add_command(label='解除此來源封鎖', command=self._unblock)
        menu.add_separator(); menu.add_command(label='反向 DNS 偵測', command=self._reverse_lookup)
        menu.add_command(label='加入白名單', command=self._allow_selected)
        def popup(event):
            item = self.table.identify_row(event.y)
            if item: self.table.selection_set(item); menu.tk_popup(event.x_root, event.y_root)
        self.table.bind('<Button-3>', popup)
        whitelist = ttk.Frame(notebook, padding=14); notebook.add(whitelist, text='白名單')
        ttk.Label(whitelist, text='暫定可信來源｜新增來源不會自動取得信任', font=('Microsoft JhengHei UI', 13, 'bold')).pack(anchor='w')
        allow_area = ttk.Frame(whitelist); allow_area.pack(fill='both', expand=True, pady=12)
        self.allow_box = tk.Listbox(allow_area, bg=c['panel'], fg=c['text'], font=('Consolas', 13),
                                   borderwidth=0, highlightthickness=0, selectbackground='#24597d', height=9)
        self.allow_box.pack(side='left', fill='both', expand=True)
        allow_scroll = ttk.Scrollbar(allow_area, orient='vertical', command=self.allow_box.yview)
        self.allow_box.configure(yscrollcommand=allow_scroll.set); allow_scroll.pack(side='right', fill='y')
        wl_buttons = ttk.Frame(whitelist); wl_buttons.pack(fill='x')
        for label, command in [('新增 IP／CIDR', self._add_allow), ('移除選取', self._remove_allow),
                               ('匯入白名單 JSON', self._import_allow), ('匯出白名單', self._export_allow)]:
            ttk.Button(wl_buttons, text=label, command=command).pack(side='left', padx=(0, 8))
        self._refresh_allow()
        intel = ttk.Frame(notebook, padding=14); notebook.add(intel, text='IP 情資')
        ttk.Label(intel, text='操作人員匯入的來源註記', font=('Microsoft JhengHei UI', 13, 'bold')).pack(anchor='w')
        ttk.Label(intel, text='GEO 與對象 IP 僅供人工核對；不會加入白名單、黑名單或觸發自動封鎖。',
                  style='Muted.TLabel').pack(anchor='w', pady=(4, 12))
        intel_grid = ttk.Frame(intel); intel_grid.pack(fill='both', expand=True)
        for column, (kind, heading) in enumerate((('geo_sources', 'GEO 網段 / 區域標籤'),
                                                  ('object_ips', '需關注的對象 IP / CIDR'))):
            intel_grid.columnconfigure(column, weight=1)
            panel = ttk.Frame(intel_grid, padding=(0, 0, 8, 0))
            panel.grid(row=0, column=column, sticky='nsew')
            ttk.Label(panel, text=heading, font=('Microsoft JhengHei UI', 11, 'bold')).pack(anchor='w')
            frame = ttk.Frame(panel); frame.pack(fill='both', expand=True, pady=(8, 8))
            box = tk.Listbox(frame, bg=c['panel'], fg=c['text'], font=('Consolas', 11),
                             borderwidth=1, relief='solid', height=10)
            box.pack(side='left', fill='both', expand=True)
            bar = ttk.Scrollbar(frame, orient='vertical', command=box.yview)
            box.configure(yscrollcommand=bar.set); bar.pack(side='right', fill='y')
            if kind == 'geo_sources': self.geo_box = box
            else: self.object_box = box
            ttk.Button(panel, text='匯入 JSON / CSV / TXT',
                       command=lambda selected=kind: self._import_list_file(selected)).pack(anchor='w')
        self._refresh_ip_intel()
        logs = ttk.Frame(notebook, padding=8); notebook.add(logs, text='操作紀錄')
        log_area = ttk.Frame(logs); log_area.pack(fill='both', expand=True)
        self.log_box = tk.Text(log_area, bg=c['panel'], fg=c['text'], font=('Microsoft JhengHei UI', 10), wrap='word',
                               borderwidth=0, state='disabled', padx=12, pady=10)
        self.log_box.pack(side='left', fill='both', expand=True)
        log_scroll = ttk.Scrollbar(log_area, orient='vertical', command=self.log_box.yview)
        self.log_box.configure(yscrollcommand=log_scroll.set); log_scroll.pack(side='right', fill='y')
        ttk.Button(logs, text='匯出事件 JSONL', command=self._export_log).pack(anchor='e', pady=8)
        tools_tab = ttk.Frame(notebook, padding=14); notebook.add(tools_tab, text='防禦診斷工具箱')
        ttk.Label(tools_tab, text='Blue Team 防禦診斷', font=('Segoe UI', 14, 'bold')).pack(anchor='w')
        ttk.Label(tools_tab, text='只執行明確指定的盤點與診斷；不修改服務、不執行 exploit。', style='Muted.TLabel').pack(anchor='w', pady=(4, 12))
        toolbar = ttk.Frame(tools_tab); toolbar.pack(fill='x')
        self.diag_target = tk.StringVar(value='127.0.0.1')
        ttk.Label(toolbar, text='診斷目標').grid(row=0, column=0, sticky='w', padx=(0, 8))
        ttk.Entry(toolbar, textvariable=self.diag_target, width=28).grid(row=0, column=1, sticky='w')
        for index, (label, fn) in enumerate([('工具檢查', self._diagnostic_status), ('選取 PHP 執行檔', self._select_php_executable), ('PHP 攻擊鏈稽核', self._diagnostic_php), ('PHP 日誌分析', self._diagnostic_php_log), ('PHP 健康檢查', self._diagnostic_http), ('Nmap 盤點', self._diagnostic_nmap), ('TShark 介面', self._diagnostic_tshark), ('iPerf3 診斷', self._diagnostic_iperf), ('本機連線', self._diagnostic_connections), ('PHP / Java 程序盤點', self._diagnostic_runtime)]):
            button = ttk.Button(toolbar, text=label, command=fn)
            button.grid(row=1 + index // 4, column=index % 4, sticky='ew', padx=(0, 8), pady=(8, 0))
            if label == 'PHP / Java 程序盤點': self.runtime_button = button
        self.logwatch_button = ttk.Button(toolbar, text='開始監看日誌', command=self._toggle_logwatch)
        self.logwatch_button.grid(row=3, column=2, sticky='ew', padx=(0, 8), pady=(8, 0))
        for col in range(4): toolbar.columnconfigure(col, weight=1)
        self.php_binary_var = tk.StringVar(value='PHP 執行檔：使用 PATH 搜尋；CLI 設定仍須與實際 Web worker 核對。')
        self.runtime_path_button = ttk.Button(toolbar, text='採用程序中的 PHP', command=self._use_runtime_php,
                                               state='disabled')
        self.runtime_path_button.grid(row=0, column=2, sticky='ew', padx=(8, 0))
        ttk.Label(tools_tab, textvariable=self.php_binary_var, style='Muted.TLabel', wraplength=800).pack(anchor='w', pady=(8, 0))
        diag_area = ttk.Frame(tools_tab); diag_area.pack(fill='both', expand=True, pady=(12, 0))
        self.diag_output = tk.Text(diag_area, bg=c['panel'], fg=c['text'], font=('Consolas', 10), wrap='word', height=18, borderwidth=1, padx=10, pady=10)
        self.diag_output.pack(side='left', fill='both', expand=True)
        diag_scroll = ttk.Scrollbar(diag_area, orient='vertical', command=self.diag_output.yview)
        self.diag_output.configure(yscrollcommand=diag_scroll.set); diag_scroll.pack(side='right', fill='y')
        for widget in (self.service_table, self.connection_table, self.table, self.allow_box,
                       self.geo_box, self.object_box, self.log_box, self.diag_output):
            widget.bind('<MouseWheel>', self._scroll_page)

    def _open_logs(self, _event=None):
        self.notebook.select(self.log_box.master.master)
        self.root.update_idletasks()
        self.page_canvas.yview_moveto(1)
        self.log_box.focus_set()
        return 'break'

    def _scroll_page(self, event):
        """Scroll the hovered list first, then continue into the outer page at its edge."""
        if not event.delta:
            return 'break'
        units = -max(1, abs(event.delta) // 120) if event.delta > 0 else max(1, abs(event.delta) // 120)
        widget = event.widget
        if widget.winfo_class() in ('Treeview', 'Text', 'Listbox'):
            first, last = widget.yview()
            if (units < 0 and first > 0) or (units > 0 and last < 1):
                widget.yview_scroll(units, 'units')
                return 'break'
        self.page_canvas.yview_scroll(units, 'units')
        return 'break'

    def log(self, message):
        line = dt.datetime.now().astimezone().strftime('%H:%M:%S') + '  ' + message
        self.log_box.configure(state='normal'); self.log_box.insert('end', line+'\n')
        if int(self.log_box.index('end-1c').split('.')[0]) > 1000: self.log_box.delete('1.0', '101.0')
        self.log_box.see('end'); self.log_box.configure(state='disabled')
        append_event(self.data_dir / 'events.jsonl', {'message': message})

    def _worker(self):
        while True:
            kind, source, reason = self.jobs.get()
            if kind == 'stop': return
            try:
                if kind == 'block' and reason and reason.startswith('自動') and (not self.auto or self.paused):
                    self.results.put((kind,source,reason,{'blocked':False,'cancelled':True},None));continue
                mapping = dict(check='Check', poll='Poll', block='Block', unblock='Unblock', blocks='Blocks')
                result = self.backend.call(mapping[kind], source)
                self.results.put((kind, source, reason, result, None))
            except Exception as exc:
                self.results.put((kind, source, reason, None, str(exc)))

    def _snapshot_worker(self):
        while not self.closed:
            try:
                result = (self._service_snapshot(), self._connection_snapshot())
                self.results.put(('snapshot', None, None, result, None))
            except Exception as exc:
                self.results.put(('snapshot', None, None, None, str(exc)))
            for _ in range(50):
                if self.closed: return
                time.sleep(0.1)

    def _poll(self, schedule=True):
        if not self.paused and not self.poll_pending:
            self.poll_pending=True; self.jobs.put(('poll', None, None))
        if schedule and not self.closed: self.root.after(5000, self._poll)

    def _drain(self):
        while True:
            try: kind, source, reason, result, error = self.results.get_nowait()
            except queue.Empty: break
            if kind == 'poll': self.poll_pending=False
            if kind == 'diagnostic': self.diag_busy=False
            if source and kind in ('block', 'unblock'): self.pending.discard(source)
            if error:
                if kind == 'logwatch':
                    if self.logwatch_stop: self.logwatch_stop.set()
                    self.logwatch_button.configure(text='開始監看日誌')
                if kind in ('check', 'block'):
                    self.ready=False; self.auto=False; self.auto_button.configure(text='自動停止：關閉')
                self.error_count += 1
                self.status.set('操作未完成：' + error.replace('\n', ' ')[:180])
                self.log(kind+' 失敗：'+error[:600]); continue
            if kind == 'diagnostic':
                if result.tool == 'runtime-inventory':
                    self.runtime_php_paths = (result.metadata or {}).get('php_paths', [])
                    self.runtime_path_button.configure(state='normal' if len(self.runtime_php_paths) == 1 else 'disabled')
                self._diagnostic_write(result)
                continue
            if kind == 'logwatch':
                findings, skipped = result
                if skipped: self.log('日誌監看：寫入量超過 1 MiB，已跳過較早資料；請另行分析完整日誌。')
                for finding in findings:
                    self.log('日誌警示 ['+finding.severity+'] '+finding.title+'：'+finding.detail)
                continue
            if kind == 'reverse':
                hostname, detail = result
                self.log('反向 DNS：'+source+' → '+hostname)
                messagebox.showinfo('反向 DNS 偵測結果', source+'\n\n'+detail, parent=self.root)
                continue
            if kind == 'check':
                self.ready=True; self.last_firewall_check_at = dt.datetime.now(dt.timezone.utc)
                self.status.set('可控制來源封鎖 · 預設手動')
            elif kind == 'snapshot':
                self.service_rows, self.connection_rows = result
            elif kind == 'blocks':
                self.blocks={str(normalize(s)) for row in result if str(row.get('Enabled')).lower() == 'true' for s in row['Addresses']}
            elif kind == 'poll':
                self.last_poll_at = dt.datetime.now(dt.timezone.utc)
                now=time.monotonic(); counts={}
                for row in result:
                    addr=str(normalize(row['RemoteAddress'])); counts[addr]=counts.get(addr,0)+1
                try:new_sources=self.tracker.observe(counts, now)
                except ValueError as exc:
                    self.auto=False;self.auto_button.configure(text='自動停止：關閉');self.log(str(exc));continue
                for addr in new_sources:
                    self.log('MARK 未核准來源：'+addr)
                    self.rows.setdefault(addr,{})['marked_at']=dt.datetime.now().strftime('%H:%M:%S')
                for row in self.rows.values(): row['count']=0
                for addr,count in counts.items(): self.rows.setdefault(addr,{})['count']=count
                self.card_vars['update'].set(dt.datetime.now().strftime('%H:%M:%S'))
                self.status.set('每 5 秒觀察 · 只處理 TCP 8080' if self.ready else '僅觀察；尚未通過封鎖權限檢查')
                if self.auto and self.ready and not self.paused:
                    due=[s for s in self.tracker.due(now) if s not in self.pending and s not in self.blocks]
                    if due: self._request_block(due[0], '自動：首次標記超過 180 秒')
            elif kind == 'block':
                if not result.get('blocked'): self.log(('已取消排隊的自動停止：' if result.get('cancelled') else '封鎖未驗證：')+source); continue
                self.blocks.add(source)
                if source in self.tracker.marks: self.tracker.marks[source]['blocked']=True
                self.log('已啟用來源封鎖：'+source+'；未宣稱 TCP 已立即關閉')
            elif kind == 'unblock':
                self.blocks.discard(source)
                if source in self.tracker.marks: self.tracker.marks[source].update(blocked=False,unblock_hold=True)
                self.log('已解除來源封鎖：'+source+'；本次監看暫停對它自動封鎖')
        self._render()
        if not self.closed: self.root.after(150, self._drain)

    def _render(self):
        def set_if_changed(var, value):
            value = str(value)
            if var.get() != value: var.set(value)
        selection=self.table.selection()
        existing=set(self.table.get_children())
        for source in sorted(set(self.rows)|self.blocks):
            row=self.rows.get(source,{}); mark=self.tracker.marks.get(source)
            trusted=self.tracker.trusted(source); blocked=source in self.blocks
            state='已封鎖' if blocked else ('白名單' if trusted else '待核對')
            timer='—'
            if mark and not blocked:
                remaining=max(0,181-int(time.monotonic()-mark['first']))
                timer=('手動控制' if not self.auto else ('已到門檻' if not remaining else str(remaining)+' 秒'))
                if mark['unblock_hold']: timer='已手動暫緩'
                elif not mark['active']: timer='暫無連線'
            action='來源流量封鎖規則已啟用' if blocked else ('保留正常連入' if trusted else '等待核對／手動停止')
            if source in self.pending: action='處理中…'
            values=(source,state,row.get('count',0),row.get('marked_at','—'),timer,action)
            tag='blocked' if blocked else ('trusted' if trusted else 'unknown')
            if source in existing:
                if self.table.item(source, 'values') != tuple(map(str, values)) or self.table.item(source, 'tags') != (tag,):
                    self.table.item(source, values=values, tags=(tag,))
            else: self.table.insert('', 'end', iid=source, values=values, tags=(tag,))
        if selection and self.table.exists(selection[0]): self.table.selection_set(selection)
        set_if_changed(self.card_vars['mode'], '自動 · 180 秒' if self.auto else '手動')
        set_if_changed(self.card_vars['unknown'], sum(1 for s,m in self.tracker.marks.items() if m['active'] and s not in self.blocks))
        set_if_changed(self.card_vars['blocked'], len(self.blocks))
        self.block_button.configure(state='normal' if self.ready else 'disabled')
        if hasattr(self, 'empty_state'):
            if self.rows or self.blocks:
                self.empty_state.place_forget()
            else:
                self.empty_state.place(relx=0, rely=0, relwidth=1, relheight=1)
                if self.paused:
                    detail = '觀察已暫停；恢復觀察後才能更新連線資料。'
                elif self.last_poll_at is None:
                    detail = '尚未取得成功取樣；請查看頂端錯誤與操作紀錄，不能據此判定沒有連線。'
                elif (dt.datetime.now(dt.timezone.utc) - self.last_poll_at).total_seconds() > 30:
                    detail = '連線資料已超過 30 秒未更新；請檢查取樣狀態後再判斷。'
                else:
                    detail = '最近成功取樣未取得來源；每 5 秒取樣可能漏掉短暫 HTTP 請求。'
                self.empty_detail.configure(text=detail)
        if hasattr(self, 'dashboard_vars'):
            snapshot = health_snapshot(started_at=self.started_at, last_poll_at=self.last_poll_at,
                                       last_firewall_check_at=self.last_firewall_check_at,
                                       queue_age_seconds=0, error_count=self.error_count,
                                       event_log=self.data_dir / 'events.jsonl', paused=self.paused)
            health_state = snapshot['state']
            label = {'HEALTHY': '取樣正常', 'STALE': '取樣逾時', 'STARTING': '等待首次取樣', 'PAUSED': '觀察已暫停', 'ERROR': '事件紀錄無法讀取'}[health_state]
            set_if_changed(self.dashboard_vars['health'], ('展示模式 · ' if self.demo else '') + label)
            set_if_changed(self.dashboard_vars['detail'], '取樣齡：' + str(snapshot['last_poll_age_seconds']) + ' 秒 · 防火牆檢查齡：' + str(snapshot['last_firewall_check_age_seconds']) + ' 秒 · 錯誤：' + str(snapshot['error_count']))
            if hasattr(self, 'service_table'):
                desired = []
                for name, port, up in self.service_rows:
                    state = '運作中' if up else '未偵測到'
                    note = '本機服務可連線' if up else '未在本機回應；不代表遠端服務故障'
                    desired.append((name, port, state, note, 'up' if up else 'down'))
                for iid, (name, port, state, note, tag) in enumerate(desired):
                    key = str(iid)
                    values = (name, port, state, note)
                    if self.service_table.exists(key):
                        if self.service_table.item(key, 'values') != tuple(map(str, values)) or self.service_table.item(key, 'tags') != (tag,): self.service_table.item(key, values=values, tags=(tag,))
                    else: self.service_table.insert('', 'end', iid=key, values=values, tags=(tag,))
            if hasattr(self, 'connection_table'):
                rows = self.connection_rows
                for index, row in enumerate(rows):
                    key = 'connection-'+str(index)
                    if self.connection_table.exists(key):
                        if self.connection_table.item(key, 'values') != tuple(map(str, row)): self.connection_table.item(key, values=row)
                    else: self.connection_table.insert('', 'end', iid=key, values=row)
                for iid in self.connection_table.get_children()[len(rows):]: self.connection_table.delete(iid)

    def _tick(self):
        self._render()
        if not self.closed: self.root.after(1000,self._tick)

    def _selected(self):
        items=self.table.selection()
        if not items: messagebox.showinfo('選取來源','請先選取一個來源 IP。');return None
        return items[0]

    def _reverse_lookup(self):
        source = self._selected()
        if not source: return
        def lookup():
            try:
                hostname, aliases, addresses = socket.gethostbyaddr(source)
                detail = hostname
                if aliases: detail += '\n別名：' + '、'.join(aliases)
                if addresses: detail += '\n解析位址：' + '、'.join(addresses)
            except (socket.herror, socket.gaierror, OSError):
                hostname, detail = '無 PTR 記錄', '沒有可解析的 PTR／主機名稱。'
            self.results.put(('reverse', source, None, (hostname, detail), None))
        threading.Thread(target=lookup, daemon=True).start()

    def _request_block(self, source, reason):
        if not self.ready or self.tracker.trusted(source) or source in self.pending or source in self.blocks: return
        self.log('申請封鎖：'+source+' / '+reason)
        self.pending.add(source); self.jobs.put(('block',source,reason))

    def _manual_block(self):
        source=self._selected()
        if not source:return
        if self.tracker.trusted(source): messagebox.showinfo('保護合法來源','白名單來源不能直接停止；請先核對並調整白名單。');return
        if not self.ready: messagebox.showerror('尚未就緒','封鎖權限或防火牆檢查未通過。');return
        if messagebox.askyesno('停止來源連入', '封鎖 '+source+' 對 TCP 8080 的流量？\n不會終止 Java／PHP／資料庫。'):
            self._request_block(source,'操作人員手動停止')

    def _unblock(self):
        source=self._selected()
        if source and source in self.blocks and source not in self.pending:
            self.log('申請解除封鎖：'+source);self.pending.add(source);self.jobs.put(('unblock',source,None))

    def _toggle_auto(self):
        if self.auto:
            self.auto=False
        else:
            if not self.ready or not self.policy['allowed_sources']:
                messagebox.showwarning('尚不能啟用','先匯入／建立白名單，並確認防火牆與管理員權限。');return
            if not messagebox.askyesno('啟用自動停止','未知來源首次標記超過 180 秒且仍有連線時，會建立來源封鎖。\n重新連線不會重設計時。這可能影響未列入白名單的合法設備。\n\n啟用？'):return
            self.auto=True
        self.auto_button.configure(text='自動停止：開啟' if self.auto else '自動停止：關閉')
        self.log('自動停止模式：'+('開啟' if self.auto else '關閉'))

    def _firewall_check(self):
        """重新驗證 Windows Firewall；實際寫入仍只由 Block/Unblock 工作佇列執行。"""
        self.ready = False
        self.auto = False
        self.auto_button.configure(text='自動停止：關閉')
        self.status.set('正在重新檢查 Windows Firewall 與 TCP 8080 規則…')
        if not self.pending:
            self.jobs.put(('check', None, None))

    def _diagnostic_write(self, result):
        self.diag_output.delete('1.0', 'end')
        self.diag_output.insert('end', '[' + result.tool + '] ' + ('完成\n\n' if result.ok else '未完成\n\n') + result.output)
        self.log('防禦診斷 ' + result.tool + (' 完成' if result.ok else '未完成'))

    def _launch_diagnostic(self, tool, fn, *args):
        if self.diag_busy:
            messagebox.showinfo('診斷進行中', '請等待目前的診斷完成。', parent=self.root)
            return
        self.diag_busy=True
        self.diag_output.delete('1.0', 'end')
        self.diag_output.insert('end', tool+' 正在執行…')
        def run():
            try:
                result=fn(*args)
                self.results.put(('diagnostic', None, None, result, None))
            except Exception as exc:
                self.results.put(('diagnostic', None, None, None, str(exc)))
        threading.Thread(target=run, daemon=True).start()

    @staticmethod
    def _audit_result(tool, fn, *args):
        findings=fn(*args)
        output='\n\n'.join(f'[{f.severity}] {f.title}\n{f.detail}\n建議：{f.remediation}' for f in findings)
        return ToolResult(tool, True, output or '沒有產生稽核項目。')

    def _diagnostic_status(self):
        self.diag_output.delete('1.0', 'end')
        self.diag_output.insert('end', '\n'.join(f'{k}: ' + ('可用' if v else '未安裝') for k, v in tool_status().items()))

    def _diagnostic_nmap(self):
        self._launch_diagnostic('nmap', nmap_inventory, self.diag_target.get().strip())

    def _diagnostic_http(self):
        target=self.diag_target.get().strip()
        if not target.startswith('http://') and not target.startswith('https://'):
            target='http://'+target+':8080/'
        self._launch_diagnostic('http-probe', http_probe, target)

    def _select_php_executable(self):
        path = filedialog.askopenfilename(title='選取實際 PHP 執行檔', filetypes=[('Executable files', '*.exe'), ('All files', '*.*')])
        if path:
            self.php_executable = path
            self.php_binary_var.set('PHP 執行檔：' + path + '；仍須確認 Web worker 使用相同版本與設定。')

    def _use_runtime_php(self):
        if len(self.runtime_php_paths) != 1: return
        path = self.runtime_php_paths[0]
        if not Path(path).is_file():
            messagebox.showerror('無法採用', '盤點時的 PHP 執行檔已不存在或無法讀取，請重新盤點。', parent=self.root)
            return
        self.php_executable = path
        self.php_binary_var.set('PHP 執行檔：' + path + '；由本機執行中程序選取，仍須核對 Web worker。')

    def _diagnostic_php(self):
        self._launch_diagnostic('PHP 攻擊鏈稽核', self._audit_result, 'PHP 攻擊鏈稽核', audit_php_config, None, self.php_executable)

    def _diagnostic_php_log(self):
        path=filedialog.askopenfilename(title='選取 PHP／Web Server 日誌', filetypes=[('Log files','*.log *.txt *.csv'),('All files','*.*')])
        if not path:return
        self._launch_diagnostic('PHP 日誌分析', self._audit_result, 'PHP 日誌分析', audit_log_file, path)

    def _toggle_logwatch(self):
        if self.logwatch_stop and not self.logwatch_stop.is_set():
            self.logwatch_stop.set()
            self.logwatch_button.configure(text='開始監看日誌')
            self.log('已停止 PHP／Web 日誌監看。')
            return
        path = filedialog.askopenfilename(title='選取要持續監看的 PHP／Web 日誌',
                                          filetypes=[('Log files', '*.log *.txt'), ('All files', '*.*')])
        if not path: return
        stop = threading.Event()
        self.logwatch_stop = stop
        self.logwatch_button.configure(text='停止監看日誌')
        self.log('已開始唯讀監看日誌新增內容；不讀取舊紀錄，不自動封鎖。')
        def watch():
            monitor = LogTailMonitor(path)
            while not stop.is_set():
                try:
                    findings, skipped = monitor.poll()
                    if findings or skipped:
                        self.results.put(('logwatch', None, None, (findings, skipped), None))
                except OSError as exc:
                    self.results.put(('logwatch', None, None, None, str(exc)))
                    return
                stop.wait(2)
        threading.Thread(target=watch, daemon=True).start()

    def _diagnostic_tshark(self):
        self._launch_diagnostic('tshark', tshark_interfaces)

    def _diagnostic_iperf(self):
        self._launch_diagnostic('iperf3', iperf3_probe, self.diag_target.get().strip())

    def _diagnostic_connections(self):
        self._launch_diagnostic('netstat', local_connections)

    def _diagnostic_runtime(self):
        self._launch_diagnostic('runtime-inventory', runtime_inventory)

    def _service_snapshot(self):
        services = [('PHP／Tomcat', 8080), ('AnyDesk', 7070), ('VNC', 5900), ('SMB', 445), ('TeamViewer', 5938)]
        return [(name, port, self.demo or self._port_open(port)) for name, port in services]

    def _connection_snapshot(self):
        service_by_port = {8080: 'PHP／Tomcat', 7070: 'AnyDesk', 5900: 'VNC', 445: 'SMB', 5938: 'TeamViewer'}
        if self.demo:
            return [('192.0.2.25', 'PHP／Tomcat', 8080, 'ESTABLISHED', 1000), ('192.0.2.31', 'AnyDesk', 7070, 'ESTABLISHED', 1001)]
        rows = []
        try:
            completed = subprocess.run(['netstat', '-ano', '-p', 'TCP'], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=3, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            for line in completed.stdout.splitlines():
                parts = line.split()
                if len(parts) < 4 or parts[0].upper() != 'TCP':
                    continue
                local, remote, state, pid = parts[1], parts[2], parts[3], parts[4] if len(parts) > 4 else 'N/A'
                try: port = int(local.rsplit(':', 1)[1])
                except (ValueError, IndexError): continue
                if port not in service_by_port or state.upper() in ('LISTENING', 'LISTEN'):
                    continue
                remote_ip = remote.rsplit(':', 1)[0].strip('[]')
                rows.append((remote_ip, service_by_port[port], port, state, pid))
        except (OSError, subprocess.SubprocessError):
            pass
        return rows[:200]

    @staticmethod
    def _port_open(port):
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.15):
                return True
        except OSError:
            return False

    def _toggle_pause(self):
        self.paused=not self.paused
        if self.paused: self.auto=False;self.auto_button.configure(text='自動停止：關閉')
        self.pause_button.configure(text='恢復觀察' if self.paused else '暫停觀察')
        self.log('已暫停觀察及自動停止；既有封鎖仍保留。' if self.paused else '已恢復觀察；仍為手動模式。')

    def _refresh_allow(self):
        self.allow_box.delete(0,'end')
        for source in self.policy['allowed_sources']:self.allow_box.insert('end',source)

    def _save_allow(self, sources):
        networks=[str(ipaddress.ip_network(s,strict=True)) for s in sources]
        candidate=Tracker(networks or ['127.0.0.0/8'])
        if any(candidate.trusted(s) for s in self.blocks):raise ValueError('白名單包含仍被封鎖的來源；請先解除封鎖，再更新白名單。')
        self.policy['allowed_sources']=list(dict.fromkeys(networks))
        self.policy['inventory_approved']=False
        if not self.demo:
            temp=self.policy_path.with_suffix('.tmp');temp.write_text(json.dumps(self.policy,indent=2),encoding='utf-8');temp.replace(self.policy_path)
        self.tracker=Tracker(networks or ['127.0.0.0/8'])
        self.auto=False;self.auto_button.configure(text='自動停止：關閉')
        self._refresh_allow();self.log('白名單已更新；計時重建，自動停止已關閉。')

    def _add_allow(self):
        value=simpledialog.askstring('新增白名單','輸入單一 IP 或精確 CIDR（例如 192.0.2.25/32）：',parent=self.root)
        if value:
            try:self._save_allow(self.policy['allowed_sources']+[value.strip()])
            except ValueError as exc:messagebox.showerror('來源格式不符',str(exc))

    def _import_list_file(self, kind):
        path=filedialog.askopenfilename(title=('匯入 GEO 名單' if kind == 'geo_sources' else '匯入對象 IP'), filetypes=[('JSON/CSV/TXT','*.json *.csv *.txt'),('All files','*.*')])
        if not path:return
        try:
            values = parse_list_file(path, kind)
            updated = dict(self.policy, **{kind: values})
            if not self.demo: self._persist_policy(updated)
        except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
            messagebox.showerror('名單匯入失敗', str(exc), parent=self.root)
            return
        self.policy = updated
        self._refresh_ip_intel()
        self.log(('GEO' if kind=='geo_sources' else '對象 IP')+' 名單已匯入：'+str(len(self.policy[kind]))+' 筆')

    def _refresh_ip_intel(self):
        self.geo_box.delete(0, 'end')
        for row in self.policy['geo_sources']:
            if isinstance(row, dict) and 'cidr' in row and 'label' in row:
                self.geo_box.insert('end', str(row['cidr']) + '   ' + str(row['label']))
            else:
                self.geo_box.insert('end', str(row) + '   （舊版格式，請重新匯入）')
        self.object_box.delete(0, 'end')
        for value in self.policy['object_ips']:
            self.object_box.insert('end', value)

    def _show_ip_intel(self):
        source = self._selected()
        if not source: return
        region, watched = classify(source, self.policy['geo_sources'], self.policy['object_ips'])
        messagebox.showinfo('IP 情資比對', source + '\n\nGEO：' + region +
                            '\n對象 IP：' + ('命中' if watched else '未命中') +
                            '\n\n資料由操作人員匯入，不能單獨作為封鎖依據。', parent=self.root)

    def _persist_policy(self, policy=None):
        temp=self.policy_path.with_suffix('.tmp'); temp.write_text(json.dumps(policy or self.policy,indent=2,ensure_ascii=False),encoding='utf-8'); temp.replace(self.policy_path)

    def _allow_selected(self):
        source=self._selected()
        if not source:return
        if source in self.blocks:
            messagebox.showinfo('先解除封鎖','請先解除此來源的封鎖，成功後再加入白名單。');return
        if messagebox.askyesno('確認可信來源','確認 '+source+' 是合法來源並加入白名單？'):
            self._save_allow(self.policy['allowed_sources']+[source])

    def _remove_allow(self):
        items=self.allow_box.curselection()
        if items and messagebox.askyesno('移除白名單','移除後此來源將成為待核對來源；不會立即封鎖。'):
            self._save_allow([s for i,s in enumerate(self.policy['allowed_sources']) if i!=items[0]])

    def _import_allow(self):
        path=filedialog.askopenfilename(title='選擇白名單',filetypes=[('JSON','*.json')])
        if not path:return
        try:
            data=json.loads(Path(path).read_text(encoding='utf-8-sig'))
            sources=data['allowed_sources'] if isinstance(data,dict) else data
            if not isinstance(sources,list):raise ValueError('須為來源陣列')
            self._save_allow(sources)
        except (OSError,ValueError,KeyError,TypeError) as exc:messagebox.showerror('匯入失敗',str(exc))

    def _export_allow(self):
        path=filedialog.asksaveasfilename(defaultextension='.json',initialfile='allowlist.json')
        if path:Path(path).write_text(json.dumps(dict(allowed_sources=self.policy['allowed_sources']),indent=2),encoding='utf-8')

    def _export_log(self):
        path=filedialog.asksaveasfilename(defaultextension='.jsonl',initialfile='PHPtoSHELL-events.jsonl')
        if path:shutil.copyfile(self.data_dir/'events.jsonl',path)

    def _close(self):
        if self.pending and not messagebox.askyesno('仍有操作進行中','操作可能仍會完成。確定關閉？既有規則不會自動解除。'):return
        self.auto=False;self.closed=True
        if self.logwatch_stop: self.logwatch_stop.set()
        self.log('控制台關閉；自動停止已停用，既有來源封鎖仍保留。')
        self.jobs.put(('stop',None,None));self.root.destroy()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--demo',action='store_true')
    parser.add_argument('--data-dir',type=Path)
    parser.add_argument('--smoke-test',action='store_true')
    args=parser.parse_args()
    directory=args.data_dir or Path(os.environ.get('LOCALAPPDATA',str(Path.home())))/('PHPtoSHELLDemo' if args.demo else 'PHPtoSHELL')
    root=tk.Tk()
    try:
        app=App(root,directory,args.demo)
        if args.smoke_test:
            if not args.demo:raise ValueError('Smoke test requires --demo')
            root.after(2000,lambda:(root.update_idletasks(),root.destroy()))
        root.mainloop()
    except Exception as exc:
        messagebox.showerror('PHPtoSHELL 啟動失敗',str(exc));raise


if __name__=='__main__':main()
