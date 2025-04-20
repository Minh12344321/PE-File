import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pe_parser import parse_pe

class PEViewerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PE Viewer")

        # Tạo khung
        frame = ttk.Frame(root)
        frame.pack(fill=tk.BOTH, expand=True)

        # TreeView bên trái
        self.tree = ttk.Treeview(frame)
        self.tree.heading("#0", text="Structure")
        self.tree.pack(side=tk.LEFT, fill=tk.Y)

        # ListView bên phải
        self.list = ttk.Treeview(frame, columns=("Address", "Value", "Meaning"), show="headings")
        self.list.heading("Address", text="Address")
        self.list.heading("Value", text="Value")
        self.list.heading("Meaning", text="Meaning")
        self.list.column("Address", width=100)
        self.list.column("Value", width=100)
        self.list.column("Meaning", width=400)
        self.list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Menu
        menubar = tk.Menu(root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Open", command=self.open_file)
        filemenu.add_command(label="Exit", command=root.quit)
        menubar.add_cascade(label="File", menu=filemenu)
        root.config(menu=menubar)

        # Gán sự kiện click vào Tree
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)

        self.data = None

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
            messagebox.showerror("Error", f"Failed to parse file:\n{e}")

    def populate_tree(self):
        self.tree.delete(*self.tree.get_children())
        for key in self.data.keys():
            self.tree.insert('', 'end', iid=key, text=key)

    def on_tree_select(self, event):
        selected = self.tree.focus()
        if not selected:
            return
        self.list.delete(*self.list.get_children())
        if selected in self.data:
            for addr, val, name in self.data[selected]:
                self.list.insert('', 'end', values=(addr, val, name))
        else:
            messagebox.showinfo("No Data", f"No detailed data available for {selected}.")

if __name__ == "__main__":
    root = tk.Tk()
    app = PEViewerApp(root)
    root.geometry("900x600")
    root.mainloop()
