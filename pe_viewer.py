import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pe_parser import parse_pe

class PEViewerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PE Viewer")

        frame = ttk.Frame(root, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        # ===== Left Frame =====
        left_frame = ttk.Frame(frame)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 5))

        self.tree = ttk.Treeview(left_frame)
        self.tree.heading("#0", text="Structure", anchor="w")
        self.tree.pack(fill=tk.Y, expand=True)

        tree_scrollbar = ttk.Scrollbar(left_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scrollbar.set)
        tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # ===== Right Frame =====
        right_frame = ttk.Frame(frame)
        right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.list = ttk.Treeview(
            right_frame,
            columns=("Index", "Address", "Value", "Meaning"),
            show="headings",
            selectmode="browse"
        )
        self.list.heading("Index", text="#")
        self.list.column("Index", width=50, anchor="center")
        self.list.pack(fill=tk.BOTH, expand=True)

        list_scrollbar = ttk.Scrollbar(right_frame, orient="vertical", command=self.list.yview)
        self.list.configure(yscrollcommand=list_scrollbar.set)
        list_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # ===== Menu =====
        menubar = tk.Menu(root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Open", command=self.open_file)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=root.quit)
        menubar.add_cascade(label="File", menu=filemenu)
        root.config(menu=menubar)

        # Event Binding
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)

        self.data = None
        self.column_config = {
            "DOS Header":       ("Property", "Value"),
            "Sections Table":   ("Name","Entropy","Raw-address (begin - end)","Raw size","Virtual address"),
           "Import Table": ("Imports", "Library", "Type", "Ordinal", "Flag"),

            "Export Table":     ("Funtion", "Name"),
            "Resource Table":   ("Name", "Footprint(sha256)", "Entropy"),
            "Relocation Table": ("RVA", "N/A", "Relocation Type"),
            "Library": ("DLL Name", "API Count"),

        }

    def open_file(self):
        file_path = filedialog.askopenfilename(
            title="Open PE File",
            filetypes=[("Executable Files", "*.exe *.dll *.sys"), ("All Files", "*.*")]
        )
        if not file_path:
            return

        try:
            self.data = parse_pe(file_path)
            self.populate_tree()
        except Exception as e:
            messagebox.showerror("Error", f"Không thể phân tích file:\n{e}")

    def populate_tree(self):
        self.tree.delete(*self.tree.get_children())
        for key in self.data.keys():
            self.tree.insert('', 'end', iid=key, text=key)

    def on_tree_select(self, event):
        selected = self.tree.focus()
        if not selected or selected not in self.data:
            return

        self.list.delete(*self.list.get_children())

        columns = self.column_config.get(selected, ("Col1", "Col2", "Col3"))
        full_columns = ("Index",) + columns
        self.list["columns"] = full_columns

        self.list.heading("Index", text="#")
        self.list.column("Index", width=50, anchor="center")

        for col in columns:
            self.list.heading(col, text=col)
            self.list.column(col, anchor="w", width=150)

        try:
            for idx, row in enumerate(self.data[selected], start=1):
                self.list.insert('', 'end', values=(idx, *row))
        except Exception as e:
            messagebox.showerror("Error", f"Lỗi hiển thị dữ liệu:\n{e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PEViewerApp(root)
    root.geometry("1100x600")
    root.mainloop()
