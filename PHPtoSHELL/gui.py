[rtk] /!\ No hook installed — run `rtk init -g` for automatic token savings
"""PHPtoSHELL ?脩戌蝔??o network listener or web UI."""
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

AUTHOR = '?恭??
VERSION = '2026.10.28'
# Windows 11 Fluent-like palette: light neutral canvas, white surfaces, restrained accent.
COLORS = dict(bg='#f3f3f3', panel='#ffffff', border='#e5e5e5', text='#1f1f1f',
              muted='#616161', blue='#0067c0', green='#107c10', amber='#9d5d00', red='#c42b1c')


def new_policy():
    return dict(version=1, port=8080, inventory_approved=False, target_computer='', allowed_sources=[])


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
        if demo:
            self.policy = new_policy(); self.policy['allowed_sources'] = ['192.0.2.25/32', '192.0.2.31/32']
        self.tracker = Tracker(self.policy['allowed_sources'] or ['127.0.0.0/8'])
        self.backend = DemoBackend() if demo else Backend(self.policy_path)
        self.jobs, self.results = queue.Queue(), queue.Queue()
        self.rows, self.blocks, self.pending = {}, set(), set()
        self.auto, self.ready, self.paused, self.poll_pending = False, False, False, False
        self.closed = False
        self._layout()
        threading.Thread(target=self._worker, daemon=True).start()
        self.jobs.put(('check', None, None)); self.jobs.put(('blocks', None, None))
        self.root.after(100, self._drain)
        self.root.after(250, self._poll)
        self.root.after(1000, self._tick)
        self.root.protocol('WM_DELETE_WINDOW', self._close)
        self.log('撌脣???蝷箸芋撘?銝???霈銝餅??脩?? if demo else '撌脣????芋撘??芸??迫?身????)

    def _layout(self):
        c = COLORS; root = self.root
        root.title('PHPtoSHELL ?脩戌蝔?嚚?皞蝳行?嗅' + (' [撅內璅∪?]' if self.demo else ''))
        root.geometry('1240x820'); root.minsize(1020, 720); root.configure(bg=c['bg'])
        self.style = ttk.Style(root); self.style.theme_use('clam')
        self.style.configure('.', font=('Microsoft JhengHei UI', 10), background=c['bg'], foreground=c['text'])
        self.style.configure('TFrame', background=c['bg'])
        self.style.configure('Card.TFrame', background=c['panel'])
        self.style.configure('TLabel', background=c['bg'], foreground=c['text'])
        self.style.configure('Muted.TLabel', foreground=c['muted'])
        self.style.configure('Card.TLabel', background=c['panel'])
        self.style.configure('TButton', padding=(13, 8), background='#ffffff', foreground=c['text'], borderwidth=1, relief='flat')
        self.style.map('TButton', background=[('active', '#e5f1fb')], foreground=[('disabled', '#9a9a9a')])
        self.style.configure('Primary.TButton', background=c['blue'], foreground='white')
        self.style.map('Primary.TButton', background=[('active', '#4a9bff')])
        self.style.configure('Danger.TButton', background='#fde7e9', foreground='#a4262c')
        self.style.configure('Treeview', background='#ffffff', fieldbackground='#ffffff', foreground=c['text'],
                             rowheight=38, borderwidth=0)
        self.style.configure('Treeview.Heading', background='#f7f7f7', foreground=c['muted'], padding=9)
        self.style.map('Treeview', background=[('selected', '#dbeeff')], foreground=[('selected', '#1f1f1f')])
        self.style.configure('TNotebook', background=c['bg'], borderwidth=0)
        self.style.configure('TNotebook.Tab', padding=(20, 10), background='#eaeaea', foreground=c['muted'])
        self.style.map('TNotebook.Tab', background=[('selected', '#ffffff')], foreground=[('selected', c['text'])])
        outer = ttk.Frame(root, padding=24); outer.pack(fill='both', expand=True)
        header = ttk.Frame(outer); header.pack(fill='x')
        ttk.Label(header, text='INGRESS GUARD', font=('Segoe UI', 23, 'bold')).pack(side='left')
        ttk.Label(header, text='PHPtoSHELL 靘??脩戌?批?? /  TCP 8080', style='Muted.TLabel').pack(side='left', padx=20)
        ttk.Label(header, text=('DEMO 繚 ' if self.demo else 'v')+VERSION+' 繚 '+AUTHOR, foreground=c['green']).pack(side='right')
        ttk.Label(outer, text='璅??芰靘? ??閫撖?180 蝘????曹?瘙箏????迫?????甇?,
                  style='Muted.TLabel').pack(anchor='w', pady=(6, 18))
        cards = ttk.Frame(outer); cards.pack(fill='x')
        self.card_vars = {}
        for index, (key, title, initial) in enumerate([('mode', '?批璅∪?', '??'), ('unknown', '敺撠?皞?, '0'),
                                                     ('blocked', '?砍極?瑕歇撠?', '0'), ('update', '?餈??, '蝑?鞈?')]):
            cards.columnconfigure(index, weight=1)
            card = ttk.Frame(cards, style='Card.TFrame', padding=16); card.grid(row=0, column=index, sticky='ew', padx=(0, 10 if index < 3 else 0))
            ttk.Label(card, text=title, style='Card.TLabel', foreground=c['muted']).pack(anchor='w')
            var = tk.StringVar(value=initial); self.card_vars[key] = var
            ttk.Label(card, textvariable=var, style='Card.TLabel', font=('Microsoft JhengHei UI', 19, 'bold')).pack(anchor='w', pady=(6, 0))
        controls = ttk.Frame(outer); controls.pack(fill='x', pady=16)
        self.auto_button = ttk.Button(controls, text='?芸??迫嚗???, command=self._toggle_auto, style='Primary.TButton')
        self.auto_button.pack(side='left')
        self.firewall_button = ttk.Button(controls, text='瑼Ｘ Windows Firewall', command=self._firewall_check)
        self.firewall_button.pack(side='left', padx=8)
        self.pause_button = ttk.Button(controls, text='?怠?閫撖?, command=self._toggle_pause); self.pause_button.pack(side='left', padx=8)
        ttk.Button(controls, text='蝡?湔', command=lambda: self._poll(schedule=False)).pack(side='left')
        self.status = tk.StringVar(value='甇?蝣箄??脩???瑁?甈???)
        ttk.Label(controls, textvariable=self.status, style='Muted.TLabel', wraplength=480).pack(side='right')
        # Dashboard嚗??拙??Ｘ?撌亙????嚗????????銝剖蝚砌??澆閬???        dashboard = ttk.Frame(outer, style='Card.TFrame', padding=14); dashboard.pack(fill='x', pady=(0, 14))
        dashboard.columnconfigure(1, weight=1); dashboard.columnconfigure(3, weight=1)
        ttk.Label(dashboard, text='SECURITY DASHBOARD', style='Card.TLabel', font=('Segoe UI', 11, 'bold')).grid(row=0, column=0, columnspan=4, sticky='w')
        self.dashboard_vars = {}
        for col, (key, label, color) in enumerate((('connections','?桀????','#55c2ff'), ('unknown','敺???皞?,'#f5b94c'), ('blocked','撌脣???皞?,'#ff6b78'), ('health','???亙熒','#65d39a'))):
            box = ttk.Frame(dashboard, style='Card.TFrame', padding=(10, 7)); box.grid(row=1, column=col, sticky='ew', padx=(0 if col == 0 else 8, 0))
            ttk.Label(box, text=label, style='Card.TLabel', foreground='#91a9bb').pack(anchor='w')
            var = tk.StringVar(value='--'); self.dashboard_vars[key] = var
            ttk.Label(box, textvariable=var, style='Card.TLabel', foreground=color, font=('Segoe UI', 17, 'bold')).pack(anchor='w')
        ttk.Label(dashboard, text='????改?AnyDesk 7070 繚 VNC 5900 繚 SMB 445 繚 TeamViewer 5938 繚 PHP/Tomcat 8080', style='Card.TLabel', foreground='#91a9bb').grid(row=2, column=0, columnspan=4, sticky='w', pady=(10, 0))
        notebook = ttk.Notebook(outer); notebook.pack(fill='both', expand=True)
        dash_tab = ttk.Frame(notebook, padding=12); notebook.add(dash_tab, text='Dashboard')
        self.service_table = ttk.Treeview(dash_tab, columns=('service','port','state','note'), show='headings', height=7)
        for name, title, width in zip(('service','port','state','note'), ('??','??','???,'隤芣?'), (220, 100, 140, 600)):
            self.service_table.heading(name, text=title); self.service_table.column(name, width=width, stretch=name == 'note')
        self.service_table.tag_configure('up', foreground=COLORS['green']); self.service_table.tag_configure('down', foreground=COLORS['muted'])
        self.service_table.pack(fill='both', expand=True)
        ttk.Label(dash_tab, text='?桀????撠情', style='Card.TLabel', font=('Segoe UI', 11, 'bold')).pack(anchor='w', pady=(16, 6))
        self.connection_table = ttk.Treeview(dash_tab, columns=('remote','service','port','state','pid'), show='headings', height=6)
        for name, title, width in zip(('remote','service','port','state','pid'), ('?垢 IP','??','?祆???,'???,'PID'), (230, 180, 100, 150, 100)):
            self.connection_table.heading(name, text=title); self.connection_table.column(name, width=width, stretch=name == 'remote')
        self.connection_table.pack(fill='both', expand=True)
        ttk.Label(dash_tab, text='Dashboard ?芾??璈???撠???隞?銝剖??皞????蝐扎?, style='Muted.TLabel').pack(anchor='w', pady=(10, 0))
        tab = ttk.Frame(notebook, padding=(0, 12)); notebook.add(tab, text='靘????')
        cols = ('source', 'state', 'count', 'first', 'timer', 'action')
        self.table = ttk.Treeview(tab, columns=cols, show='headings', selectmode='browse')
        for name, title, width in zip(cols, ['靘? IP', '???, '?????, '擐活璅?', '?芸??迫?', '??蝯?'], [225, 135, 75, 120, 130, 300]):
            self.table.heading(name, text=title); self.table.column(name, width=width, minwidth=65, stretch=name in ('source','action'))
        self.table.tag_configure('trusted', foreground=c['green'])
        self.table.tag_configure('unknown', foreground=c['amber'])
        self.table.tag_configure('blocked', foreground=c['red'])
        scroll = ttk.Scrollbar(tab, orient='vertical', command=self.table.yview); self.table.configure(yscrollcommand=scroll.set)
        self.table.pack(side='left', fill='both', expand=True); scroll.pack(side='right', fill='y')
        menu = tk.Menu(root, tearoff=False, bg=c['panel'], fg=c['text'])
        menu.add_command(label='?迫甇支?皞? 8080', command=self._manual_block)
        menu.add_command(label='閫?甇支?皞???, command=self._unblock)
        menu.add_separator(); menu.add_command(label='?? DNS ?菜葫', command=self._reverse_lookup)
        menu.add_command(label='??賢???, command=self._allow_selected)
        def popup(event):
            item = self.table.identify_row(event.y)
            if item: self.table.selection_set(item); menu.tk_popup(event.x_root, event.y_root)
        self.table.bind('<Button-3>', popup)
        whitelist = ttk.Frame(notebook, padding=14); notebook.add(whitelist, text='?賢???)
        ttk.Label(whitelist, text='?怠??臭縑靘?嚚憓?皞????敺縑隞?, font=('Microsoft JhengHei UI', 13, 'bold')).pack(anchor='w')
        self.allow_box = tk.Listbox(whitelist, bg=c['panel'], fg=c['text'], font=('Consolas', 13),
                                   borderwidth=0, highlightthickness=0, selectbackground='#24597d', height=9)
        self.allow_box.pack(fill='both', expand=True, pady=12)
        wl_buttons = ttk.Frame(whitelist); wl_buttons.pack(fill='x')
        for label, command in [('?啣? IP嚗IDR', self._add_allow), ('蝘駁?詨?', self._remove_allow),
                               ('?臬?賢???JSON', self._import_allow), ('?臬?賢???, self._export_allow)]:
            ttk.Button(wl_buttons, text=label, command=command).pack(side='left', padx=(0, 8))
        self._refresh_allow()
        logs = ttk.Frame(notebook, padding=8); notebook.add(logs, text='??蝝??)
        self.log_box = tk.Text(logs, bg=c['panel'], fg=c['text'], font=('Microsoft JhengHei UI', 10), wrap='word',
                               borderwidth=0, state='disabled', padx=12, pady=10)
        self.log_box.pack(fill='both', expand=True)
        ttk.Button(logs, text='?臬鈭辣 JSONL', command=self._export_log).pack(anchor='e', pady=8)
        actions = ttk.Frame(outer); actions.pack(fill='x', pady=(14, 8))
        self.block_button = ttk.Button(actions, text='?迫?詨?靘???', command=self._manual_block, style='Danger.TButton')
        self.block_button.pack(side='left')
        ttk.Button(actions, text='閫??詨?靘?撠?', command=self._unblock).pack(side='left', padx=8)
        ttk.Button(actions, text='??賢???, command=self._allow_selected).pack(side='left')
        ttk.Button(actions, text='?? DNS ?菜葫', command=self._reverse_lookup).pack(side='left', padx=8)
        ttk.Label(outer, text='???嗡?皞? 8080 ????銝?甇?Java嚗HP嚗ySQL????撘???圾?斗????,
                  style='Muted.TLabel').pack(anchor='w', pady=(4, 0))

    def log(self, message):
        line = dt.datetime.now().astimezone().strftime('%H:%M:%S') + '  ' + message
        self.log_box.configure(state='normal'); self.log_box.insert('end', line+'\n')
        if int(self.log_box.index('end-1c').split('.')[0]) > 1000: self.log_box.delete('1.0', '101.0')
        self.log_box.see('end'); self.log_box.configure(state='disabled')
        path = self.data_dir / 'events.jsonl'
        if path.exists() and path.stat().st_size > 10*1024*1024:
            path.replace(self.data_dir / 'events.previous.jsonl')
        with path.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(dict(utc=dt.datetime.now(dt.timezone.utc).isoformat(), message=message), ensure_ascii=False)+'\n')

    def _worker(self):
        while True:
            kind, source, reason = self.jobs.get()
            if kind == 'stop': return
            try:
                if kind == 'block' and reason and reason.startswith('?芸?') and (not self.auto or self.paused):
                    self.results.put((kind,source,reason,{'blocked':False,'cancelled':True},None));continue
                mapping = dict(check='Check', poll='Poll', block='Block', unblock='Unblock', blocks='Blocks')
                result = self.backend.call(mapping[kind], source)
                self.results.put((kind, source, reason, result, None))
            except Exception as exc:
                self.results.put((kind, source, reason, None, str(exc)))

    def _poll(self, schedule=True):
        if not self.paused and not self.poll_pending:
            self.poll_pending=True; self.jobs.put(('poll', None, None))
        if schedule and not self.closed: self.root.after(5000, self._poll)

    def _drain(self):
        while True:
            try: kind, source, reason, result, error = self.results.get_nowait()
            except queue.Empty: break
            if kind == 'poll': self.poll_pending=False
            if source: self.pending.discard(source)
            if error:
                if kind in ('check', 'block'):
                    self.ready=False; self.auto=False; self.auto_button.configure(text='?芸??迫嚗???)
                self.status.set('???芸???隢????)
                self.log(kind+' 憭望?嚗?+error[:600]); continue
            if kind == 'check':
                self.ready=True; self.status.set('?舀?嗡?皞???繚 ?身??')
            elif kind == 'blocks':
                self.blocks={str(normalize(s)) for row in result for s in row['Addresses']}
            elif kind == 'poll':
                now=time.monotonic(); counts={}
                for row in result:
                    addr=str(normalize(row['RemoteAddress'])); counts[addr]=counts.get(addr,0)+1
                try:new_sources=self.tracker.observe(counts, now)
                except ValueError as exc:
                    self.auto=False;self.auto_button.configure(text='?芸??迫嚗???);self.log(str(exc));continue
                for addr in new_sources:
                    self.log('MARK ?芣??皞?'+addr)
                    self.rows.setdefault(addr,{})['marked_at']=dt.datetime.now().strftime('%H:%M:%S')
                for row in self.rows.values(): row['count']=0
                for addr,count in counts.items(): self.rows.setdefault(addr,{})['count']=count
                self.card_vars['update'].set(dt.datetime.now().strftime('%H:%M:%S'))
                self.status.set('瘥?5 蝘?撖?繚 ?芾???TCP 8080' if self.ready else '??撖?撠??撠?甈?瑼Ｘ')
                if self.auto and self.ready and not self.paused:
                    due=[s for s in self.tracker.due(now) if s not in self.pending and s not in self.blocks]
                    if due: self._request_block(due[0], '?芸?嚗?甈⊥?閮???180 蝘?)
            elif kind == 'block':
                if not result.get('blocked'): self.log(('撌脣?瘨????芸??迫嚗? if result.get('cancelled') else '撠??芷?霅?')+source); continue
                self.blocks.add(source)
                if source in self.tracker.marks: self.tracker.marks[source]['blocked']=True
                self.log('撌脣??其?皞???'+source+'嚗摰?迂 TCP 撌脩??喲???)
            elif kind == 'unblock':
                self.blocks.discard(source)
                if source in self.tracker.marks: self.tracker.marks[source].update(blocked=False,unblock_hold=True)
                self.log('撌脰圾?支?皞???'+source+'嚗甈∠???摰????)
        self._render()
        if not self.closed: self.root.after(150, self._drain)

    def _render(self):
        selection=self.table.selection()
        existing=set(self.table.get_children())
        for source in sorted(set(self.rows)|self.blocks):
            row=self.rows.get(source,{}); mark=self.tracker.marks.get(source)
            trusted=self.tracker.trusted(source); blocked=source in self.blocks
            state='撌脣??? if blocked else ('?賢??? if trusted else '敺撠?)
            timer='??
            if mark and not blocked:
                remaining=max(0,181-int(time.monotonic()-mark['first']))
                timer=('???批' if not self.auto else ('撌脣?瑼? if not remaining else str(remaining)+' 蝘?))
                if mark['unblock_hold']: timer='撌脫??蝺?
                elif not mark['active']: timer='?怎???'
            action='靘?瘚?撠?閬?撌脣??? if blocked else ('靽?甇?虜??' if trusted else '蝑??詨?嚗???甇?)
            if source in self.pending: action='??銝凌?
            values=(source,state,row.get('count',0),row.get('marked_at','??),timer,action)
            tag='blocked' if blocked else ('trusted' if trusted else 'unknown')
            if source in existing: self.table.item(source, values=values, tags=(tag,))
            else: self.table.insert('', 'end', iid=source, values=values, tags=(tag,))
        if selection and self.table.exists(selection[0]): self.table.selection_set(selection)
        self.card_vars['mode'].set('?芸? 繚 180 蝘? if self.auto else '??')
        self.card_vars['unknown'].set(str(sum(1 for s,m in self.tracker.marks.items() if m['active'] and s not in self.blocks)))
        self.card_vars['blocked'].set(str(len(self.blocks)))
        self.block_button.configure(state='normal' if self.ready else 'disabled')
        if hasattr(self, 'dashboard_vars'):
            self.dashboard_vars['connections'].set(str(sum(int(v.get('count', 0)) for v in self.rows.values())))
            self.dashboard_vars['unknown'].set(str(sum(1 for s, m in self.tracker.marks.items() if m.get('active') and s not in self.blocks and not self.tracker.trusted(s))))
            self.dashboard_vars['blocked'].set(str(len(self.blocks)))
            self.dashboard_vars['health'].set('?舫霅? if self.ready else '敺炎??)
            if hasattr(self, 'service_table'):
                for iid in self.service_table.get_children():
                    self.service_table.delete(iid)
                for name, port, up in self._service_snapshot():
                    state = '??銝? if up else '?芸皜砍'
                    note = '?祆????舫??' if up else '?芸?祆???嚗?隞?”?垢????'
                    self.service_table.insert('', 'end', values=(name, port, state, note), tags=('up' if up else 'down',))
            if hasattr(self, 'connection_table'):
                for iid in self.connection_table.get_children():
                    self.connection_table.delete(iid)
                for index, row in enumerate(self._connection_snapshot()):
                    self.connection_table.insert('', 'end', iid='connection-'+str(index), values=row)

    def _tick(self):
        self._render()
        if not self.closed: self.root.after(1000,self._tick)

    def _selected(self):
        items=self.table.selection()
        if not items: messagebox.showinfo('?詨?靘?','隢??詨?銝??皞?IP??);return None
        return items[0]

    def _reverse_lookup(self):
        source = self._selected()
        if not source:
            return
        try:
            hostname, aliases, addresses = socket.gethostbyaddr(source)
            detail = hostname
            if aliases:
                detail += '\n?亙?嚗? + '??.join(aliases)
            if addresses:
                detail += '\n閫??雿?嚗? + '??.join(addresses)
            self.log('?? DNS嚗? + source + ' ??' + hostname)
            messagebox.showinfo('?? DNS ?菜葫蝯?', source + '\n\n' + detail, parent=self.root)
        except (socket.herror, socket.gaierror, OSError):
            self.log('?? DNS嚗? + source + ' ????PTR 閮?')
            messagebox.showinfo('?? DNS ?菜葫蝯?', source + '\n\n瘝??航圾?? PTR嚗蜓璈?蝔晞?, parent=self.root)

    def _request_block(self, source, reason):
        if not self.ready or self.tracker.trusted(source) or source in self.pending or source in self.blocks: return
        self.log('?唾?撠?嚗?+source+' / '+reason)
        self.pending.add(source); self.jobs.put(('block',source,reason))

    def _manual_block(self):
        source=self._selected()
        if not source:return
        if self.tracker.trusted(source): messagebox.showinfo('靽風??靘?','?賢??桐?皞??賜?亙?甇ｇ?隢??詨?銝西矽?渡???);return
        if not self.ready: messagebox.showerror('撠撠梁?','撠?甈???怎?瑼Ｘ?芷???);return
        if messagebox.askyesno('?迫靘???', '撠? '+source+' 撠?TCP 8080 ????\n銝?蝯迫 Java嚗HP嚗??澈??):
            self._request_block(source,'??鈭箏???迫')

    def _unblock(self):
        source=self._selected()
        if source and source in self.blocks and source not in self.pending:
            self.log('?唾?閫?撠?嚗?+source);self.pending.add(source);self.jobs.put(('unblock',source,None))

    def _toggle_auto(self):
        if self.auto:
            self.auto=False
        else:
            if not self.ready or not self.policy['allowed_sources']:
                messagebox.showwarning('撠??賢???,'??伐?撱箇??賢??殷?銝衣Ⅱ隤?怎??恣?甈???);return
            if not messagebox.askyesno('??芸??迫','?芰靘?擐活璅?頞? 180 蝘?隞???????遣蝡?皞??n????銝??身閮???賢蔣?踵??賢??桃???閮剖??n\n?嚗?):return
            self.auto=True
        self.auto_button.configure(text='?芸??迫嚗??? if self.auto else '?芸??迫嚗???)
        self.log('?芸??迫璅∪?嚗?+('??' if self.auto else '??'))

    def _firewall_check(self):
        """?撽? Windows Firewall嚗祕?神?乩??芰 Block/Unblock 撌乩?雿??瑁???""
        self.ready = False
        self.status.set('甇??瑼Ｘ Windows Firewall ??TCP 8080 閬???)
        if not self.pending:
            self.jobs.put(('check', None, None))

    def _service_snapshot(self):
        services = [('PHP嚗omcat', 8080), ('AnyDesk', 7070), ('VNC', 5900), ('SMB', 445), ('TeamViewer', 5938)]
        return [(name, port, self.demo or self._port_open(port)) for name, port in services]

    def _connection_snapshot(self):
        service_by_port = {8080: 'PHP嚗omcat', 7070: 'AnyDesk', 5900: 'VNC', 445: 'SMB', 5938: 'TeamViewer'}
        if self.demo:
            return [('192.0.2.25', 'PHP嚗omcat', 8080, 'ESTABLISHED', 1000), ('192.0.2.31', 'AnyDesk', 7070, 'ESTABLISHED', 1001)]
        rows = []
        try:
            completed = subprocess.run(['netstat', '-ano', '-p', 'TCP'], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=3)
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
        if self.paused: self.auto=False;self.auto_button.configure(text='?芸??迫嚗???)
        self.pause_button.configure(text='?Ｗ儔閫撖? if self.paused else '?怠?閫撖?)
        self.log('撌脫??撖??芸??迫嚗????靽??? if self.paused else '撌脫敺抵?撖?隞??璅∪???)

    def _refresh_allow(self):
        self.allow_box.delete(0,'end')
        for source in self.policy['allowed_sources']:self.allow_box.insert('end',source)

    def _save_allow(self, sources):
        networks=[str(ipaddress.ip_network(s,strict=True)) for s in sources]
        candidate=Tracker(networks or ['127.0.0.0/8'])
        if any(candidate.trusted(s) for s in self.blocks):raise ValueError('?賢??桀??思?鋡怠???靘?嚗??圾?文?????啁???)
        self.policy['allowed_sources']=list(dict.fromkeys(networks))
        self.policy['inventory_approved']=False
        if not self.demo:
            temp=self.policy_path.with_suffix('.tmp');temp.write_text(json.dumps(self.policy,indent=2),encoding='utf-8');temp.replace(self.policy_path)
        self.tracker=Tracker(networks or ['127.0.0.0/8'])
        self.auto=False;self.auto_button.configure(text='?芸??迫嚗???)
        self._refresh_allow();self.log('?賢??桀歇?湔嚗???撱綽??芸??迫撌脤???)

    def _add_allow(self):
        value=simpledialog.askstring('?啣??賢???,'頛詨?桐? IP ?移蝣?CIDR嚗?憒?192.0.2.25/32嚗?',parent=self.root)
        if value:
            try:self._save_allow(self.policy['allowed_sources']+[value.strip()])
            except ValueError as exc:messagebox.showerror('靘??澆?銝泵',str(exc))

    def _allow_selected(self):
        source=self._selected()
        if not source:return
        if source in self.blocks:
            messagebox.showinfo('?圾?文???,'隢?閫?甇支?皞?撠?嚗??????亦???);return
        if messagebox.askyesno('蝣箄??臭縑靘?','蝣箄? '+source+' ?臬?瘜?皞蒂??賢??殷?'):
            self._save_allow(self.policy['allowed_sources']+[source])

    def _remove_allow(self):
        items=self.allow_box.curselection()
        if items and messagebox.askyesno('蝘駁?賢???,'蝘駁敺迨靘?撠??箏??詨?靘?嚗????喳???):
            self._save_allow([s for i,s in enumerate(self.policy['allowed_sources']) if i!=items[0]])

    def _import_allow(self):
        path=filedialog.askopenfilename(title='?豢??賢???,filetypes=[('JSON','*.json')])
        if not path:return
        try:
            data=json.loads(Path(path).read_text(encoding='utf-8-sig'))
            sources=data['allowed_sources'] if isinstance(data,dict) else data
            if not isinstance(sources,list):raise ValueError('?靘????')
            self._save_allow(sources)
        except (OSError,ValueError,KeyError,TypeError) as exc:messagebox.showerror('?臬憭望?',str(exc))

    def _export_allow(self):
        path=filedialog.asksaveasfilename(defaultextension='.json',initialfile='allowlist.json')
        if path:Path(path).write_text(json.dumps(dict(allowed_sources=self.policy['allowed_sources']),indent=2),encoding='utf-8')

    def _export_log(self):
        path=filedialog.asksaveasfilename(defaultextension='.jsonl',initialfile='PHPtoSHELL-events.jsonl')
        if path:shutil.copyfile(self.data_dir/'events.jsonl',path)

    def _close(self):
        if self.pending and not messagebox.askyesno('隞????脰?銝?,'???航隞?摰??Ⅱ摰????Ｘ?閬?銝??芸?閫???):return
        self.auto=False;self.closed=True
        self.log('?批?圈????芸??迫撌脣??剁??Ｘ?靘?撠?隞???)
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
        messagebox.showerror('PHPtoSHELL ??憭望?',str(exc));raise


if __name__=='__main__':main()

