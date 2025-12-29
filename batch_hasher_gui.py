import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
import csv
import os
import threading
import queue
import time

APP_TITLE = "Batch Hash Processor (SHA-256)"

def sha256_hex(s: str) -> str:
    # Treat None as empty string
    if s is None:
        s = ""
    if not isinstance(s, str):
        s = str(s)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

class BatchHasherGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("980x720")

        self.msg_q = queue.Queue()
        self.worker_thread = None
        self.cancel_flag = threading.Event()

        self.csv_path = None
        self.csv_headers = []
        self.csv_has_header = tk.BooleanVar(value=True)
        self.selected_col = tk.StringVar(value="")

        self._build_ui()
        self._poll_queue()

    def _build_ui(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # Tab 1: Direct Input
        tab_input = ttk.Frame(notebook)
        notebook.add(tab_input, text="Direct Input")

        # Tab 2: CSV
        tab_csv = ttk.Frame(notebook)
        notebook.add(tab_csv, text="CSV Upload")

        # ===== Direct Input Tab =====
        input_top = ttk.Frame(tab_input)
        input_top.pack(fill="x", pady=(0, 8))

        ttk.Label(input_top, text="Input (one item per line):").pack(side="left")

        btn_frame = ttk.Frame(input_top)
        btn_frame.pack(side="right")

        ttk.Button(btn_frame, text="Hash (SHA-256)", command=self.start_hash_direct).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Clear", command=self.clear_direct).pack(side="left", padx=5)

        self.txt_input = tk.Text(tab_input, height=16, wrap="none")
        self.txt_input.pack(fill="both", expand=False)

        ttk.Label(tab_input, text="Output (CSV-style: original,sha256):").pack(anchor="w", pady=(10, 0))
        self.txt_output = tk.Text(tab_input, height=16, wrap="none")
        self.txt_output.pack(fill="both", expand=True)

        out_btns = ttk.Frame(tab_input)
        out_btns.pack(fill="x", pady=(8, 0))
        ttk.Button(out_btns, text="Copy Output", command=self.copy_output).pack(side="left")
        ttk.Button(out_btns, text="Save Output as CSV...", command=self.save_direct_output).pack(side="left", padx=8)

        # ===== CSV Tab =====
        csv_top = ttk.Frame(tab_csv)
        csv_top.pack(fill="x", pady=(0, 8))

        ttk.Button(csv_top, text="Choose CSV...", command=self.choose_csv).pack(side="left")
        self.lbl_csv = ttk.Label(csv_top, text="No file selected")
        self.lbl_csv.pack(side="left", padx=10)

        opt_frame = ttk.Frame(tab_csv)
        opt_frame.pack(fill="x", pady=(0, 8))

        ttk.Checkbutton(opt_frame, text="First row is header", variable=self.csv_has_header,
                        command=self.on_header_toggle).pack(side="left")

        ttk.Label(opt_frame, text="Column to hash:").pack(side="left", padx=(20, 6))
        self.cmb_columns = ttk.Combobox(opt_frame, textvariable=self.selected_col, state="readonly", width=30)
        self.cmb_columns.pack(side="left")

        ttk.Button(opt_frame, text="Start Hash (SHA-256)", command=self.start_hash_csv).pack(side="left", padx=12)

        ttk.Label(tab_csv, text="Preview (first 30 rows):").pack(anchor="w")
        self.tree = ttk.Treeview(tab_csv, show="headings", height=12)
        self.tree.pack(fill="both", expand=False)

        preview_scroll = ttk.Scrollbar(tab_csv, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=preview_scroll.set)
        preview_scroll.pack(side="right", fill="y")

        ttk.Label(tab_csv, text="Log:").pack(anchor="w", pady=(10, 0))
        self.txt_log = tk.Text(tab_csv, height=10, wrap="word")
        self.txt_log.pack(fill="both", expand=True)

        # ===== Bottom status/progress =====
        bottom = ttk.Frame(self.root)
        bottom.pack(fill="x", padx=10, pady=(0, 10))

        self.progress = ttk.Progressbar(bottom, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", expand=True, side="left")

        self.lbl_progress = ttk.Label(bottom, text="Idle")
        self.lbl_progress.pack(side="left", padx=10)

        self.btn_cancel = ttk.Button(bottom, text="Cancel", command=self.cancel_job, state="disabled")
        self.btn_cancel.pack(side="right")

    # ------------------- Direct Input -------------------
    def clear_direct(self):
        self.txt_input.delete("1.0", "end")
        self.txt_output.delete("1.0", "end")

    def copy_output(self):
        data = self.txt_output.get("1.0", "end-1c")
        self.root.clipboard_clear()
        self.root.clipboard_append(data)
        self.root.update()

    def save_direct_output(self):
        data = self.txt_output.get("1.0", "end-1c")
        if not data.strip():
            messagebox.showwarning(APP_TITLE, "Output is empty.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")]
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(data)
        messagebox.showinfo(APP_TITLE, f"Saved: {path}")

    def start_hash_direct(self):
        if self._job_running():
            messagebox.showwarning(APP_TITLE, "A job is already running. Cancel it first.")
            return

        raw = self.txt_input.get("1.0", "end-1c")
        items = [line.strip("\r") for line in raw.splitlines()]
        # Keep empty lines? Usually no. We'll skip empty lines.
        items = [x for x in items if x.strip() != ""]
        if not items:
            messagebox.showwarning(APP_TITLE, "No input lines to hash.")
            return

        self._start_job()
        self.txt_output.delete("1.0", "end")
        self._log_direct("Starting direct hashing...")

        def worker():
            total = len(items)
            out_lines = ["original,sha256"]
            for i, val in enumerate(items, start=1):
                if self.cancel_flag.is_set():
                    self.msg_q.put(("status", "Cancelled"))
                    self.msg_q.put(("done", None))
                    return
                h = sha256_hex(val)
                # CSV-safe minimal quoting
                orig = val.replace('"', '""')
                out_lines.append(f"\"{orig}\",{h}")
                if i % 50 == 0 or i == total:
                    self.msg_q.put(("progress", i, total))
            self.msg_q.put(("direct_output", "\n".join(out_lines)))
            self.msg_q.put(("status", f"Done ({total} items)"))
            self.msg_q.put(("done", None))

        self.worker_thread = threading.Thread(target=worker, daemon=True)
        self.worker_thread.start()

    def _log_direct(self, msg: str):
        # Direct tab uses output area only; keep status bar for progress.
        pass

    # ------------------- CSV -------------------
    def choose_csv(self):
        if self._job_running():
            messagebox.showwarning(APP_TITLE, "A job is already running. Cancel it first.")
            return

        path = filedialog.askopenfilename(
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")]
        )
        if not path:
            return
        self.csv_path = path
        self.lbl_csv.config(text=os.path.basename(path))
        self.load_csv_preview()

    def on_header_toggle(self):
        if self.csv_path:
            self.load_csv_preview()

    def load_csv_preview(self):
        self._clear_tree()
        self.csv_headers = []
        self.selected_col.set("")
        self.cmb_columns["values"] = []

        try:
            with open(self.csv_path, "r", encoding="utf-8-sig", newline="") as f:
                reader = csv.reader(f)
                rows = []
                for _ in range(31):  # header + 30 rows
                    try:
                        rows.append(next(reader))
                    except StopIteration:
                        break

            if not rows:
                messagebox.showerror(APP_TITLE, "CSV is empty.")
                return

            if self.csv_has_header.get():
                headers = rows[0]
                data_rows = rows[1:]
            else:
                max_cols = max(len(r) for r in rows)
                headers = [f"col{i+1}" for i in range(max_cols)]
                data_rows = rows

            self.csv_headers = headers
            self.cmb_columns["values"] = headers
            self.selected_col.set(headers[0] if headers else "")

            self._setup_tree(headers)
            for r in data_rows[:30]:
                padded = r + [""] * (len(headers) - len(r))
                self.tree.insert("", "end", values=padded)

            self._log_csv(f"Loaded preview: {os.path.basename(self.csv_path)}")
        except Exception as e:
            messagebox.showerror(APP_TITLE, f"Failed to read CSV:\n{e}")

    def start_hash_csv(self):
        if self._job_running():
            messagebox.showwarning(APP_TITLE, "A job is already running. Cancel it first.")
            return
        if not self.csv_path:
            messagebox.showwarning(APP_TITLE, "Choose a CSV file first.")
            return

        col_name = self.selected_col.get().strip()
        if not col_name:
            messagebox.showwarning(APP_TITLE, "Select a column to hash.")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")],
            initialfile=self._default_out_name(self.csv_path, col_name)
        )
        if not save_path:
            return

        self._start_job()
        self._log_csv(f"Starting hashing for column: {col_name}")
        self._log_csv(f"Output: {save_path}")

        def worker():
            try:
                # First pass: count rows (excluding header if present)
                total = 0
                with open(self.csv_path, "r", encoding="utf-8-sig", newline="") as f_in:
                    reader = csv.reader(f_in)
                    first = True
                    for row in reader:
                        if first and self.csv_has_header.get():
                            first = False
                            continue
                        first = False
                        total += 1

                if total == 0:
                    self.msg_q.put(("log", "No data rows found."))
                    self.msg_q.put(("status", "Done (0 rows)"))
                    self.msg_q.put(("done", None))
                    return

                # Second pass: write output with appended hash column
                with open(self.csv_path, "r", encoding="utf-8-sig", newline="") as f_in, \
                     open(save_path, "w", encoding="utf-8", newline="") as f_out:

                    reader = csv.reader(f_in)
                    writer = csv.writer(f_out)

                    if self.csv_has_header.get():
                        headers = next(reader, [])
                        if not headers:
                            raise ValueError("Header row is missing or empty.")
                        try:
                            idx = headers.index(col_name)
                        except ValueError:
                            raise ValueError(f"Column not found in header: {col_name}")

                        hash_header = f"sha256_{col_name}"
                        writer.writerow(headers + [hash_header])
                    else:
                        # No header: derive columns from first row length
                        first_row = next(reader, None)
                        if first_row is None:
                            self.msg_q.put(("status", "Done (0 rows)"))
                            self.msg_q.put(("done", None))
                            return
                        # Build synthetic headers and resolve index
                        max_cols = len(first_row)
                        headers = [f"col{i+1}" for i in range(max_cols)]
                        try:
                            idx = headers.index(col_name)
                        except ValueError:
                            # fallback: if user picked col name from dropdown it should exist
                            idx = 0
                        hash_header = f"sha256_{col_name}"
                        writer.writerow(headers + [hash_header])

                        # Process first row as data
                        if self.cancel_flag.is_set():
                            self.msg_q.put(("status", "Cancelled"))
                            self.msg_q.put(("done", None))
                            return
                        val = first_row[idx] if idx < len(first_row) else ""
                        writer.writerow(first_row + [""] * (max_cols - len(first_row)) + [sha256_hex(val)])
                        processed = 1
                        self.msg_q.put(("progress", processed, total))

                    processed = 0
                    for row in reader:
                        if self.cancel_flag.is_set():
                            self.msg_q.put(("status", "Cancelled"))
                            self.msg_q.put(("done", None))
                            return
                        # Keep row width as-is; just hash target column if present
                        val = row[idx] if idx < len(row) else ""
                        writer.writerow(row + [sha256_hex(val)])
                        processed += 1
                        if processed % 200 == 0 or processed == total:
                            self.msg_q.put(("progress", processed, total))

                self.msg_q.put(("log", f"Done. Wrote {total} rows."))
                self.msg_q.put(("status", f"Done ({total} rows)"))
                self.msg_q.put(("done", None))
            except Exception as e:
                self.msg_q.put(("error", str(e)))
                self.msg_q.put(("done", None))

        self.worker_thread = threading.Thread(target=worker, daemon=True)
        self.worker_thread.start()

    def _default_out_name(self, in_path: str, col: str) -> str:
        base = os.path.splitext(os.path.basename(in_path))[0]
        safe_col = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in col)[:40]
        return f"{base}__sha256_{safe_col}.csv"

    def _log_csv(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        self.txt_log.insert("end", f"[{ts}] {msg}\n")
        self.txt_log.see("end")

    # ------------------- Job control / UI updates -------------------
    def _job_running(self) -> bool:
        return self.worker_thread is not None and self.worker_thread.is_alive()

    def cancel_job(self):
        if self._job_running():
            self.cancel_flag.set()
            self.btn_cancel.config(state="disabled")
            self.lbl_progress.config(text="Cancelling...")

    def _start_job(self):
        self.cancel_flag.clear()
        self.progress["value"] = 0
        self.progress["maximum"] = 100
        self.lbl_progress.config(text="Working...")
        self.btn_cancel.config(state="normal")

    def _finish_job(self):
        self.btn_cancel.config(state="disabled")
        # Keep status text as-is (Done/Cancelled/Error)

    def _poll_queue(self):
        try:
            while True:
                item = self.msg_q.get_nowait()
                kind = item[0]

                if kind == "progress":
                    done, total = item[1], item[2]
                    pct = int(done * 100 / total) if total else 0
                    self.progress["value"] = pct
                    self.lbl_progress.config(text=f"{pct}% ({done}/{total})")

                elif kind == "status":
                    self.lbl_progress.config(text=item[1])

                elif kind == "direct_output":
                    self.txt_output.delete("1.0", "end")
                    self.txt_output.insert("1.0", item[1])

                elif kind == "log":
                    self._log_csv(item[1])

                elif kind == "error":
                    self.lbl_progress.config(text="Error")
                    messagebox.showerror(APP_TITLE, item[1])

                elif kind == "done":
                    self._finish_job()

        except queue.Empty:
            pass

        self.root.after(100, self._poll_queue)

    # ------------------- Tree helpers -------------------
    def _clear_tree(self):
        for col in self.tree["columns"]:
            self.tree.heading(col, text="")
        self.tree["columns"] = ()
        for i in self.tree.get_children():
            self.tree.delete(i)

    def _setup_tree(self, headers):
        self._clear_tree()
        self.tree["columns"] = headers
        for h in headers:
            self.tree.heading(h, text=h)
            self.tree.column(h, width=140, stretch=True)

    def _clear_tree_rows(self):
        for i in self.tree.get_children():
            self.tree.delete(i)

if __name__ == "__main__":
    root = tk.Tk()
    try:
        # Better default look on Windows
        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")
    except Exception:
        pass

    app = BatchHasherGUI(root)
    root.mainloop()
