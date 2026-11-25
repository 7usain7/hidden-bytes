#!/usr/bin/env python3
"""Simple Tkinter window that displays Hello (stays on current macOS full-screen Space)."""

import tkinter as tk
from pathlib import Path


def main() -> None:
    root = tk.Tk()
    root.withdraw()
    root.title("Hello")
    root.geometry("300x150")
    root.attributes("-topmost", True)

    label = tk.Label(root, text="Hello!", font=("Helvetica", 24))
    label.pack(expand=True)

    root.update_idletasks()
    root.deiconify()

    root.mainloop()


if __name__ == "__main__":
    main()
