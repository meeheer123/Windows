import tkinter as tk
from tkinter import messagebox
import subprocess
import threading
import os

def capture_fingerprint():
    """Run the C++ fingerprint capture executable."""
    try:
        result = subprocess.run(["fingerprint_app.exe"], capture_output=True, text=True)
        if result.returncode == 0:
            messagebox.showinfo("Success", "Fingerprint captured and saved successfully!")
        else:
            messagebox.showerror("Error", f"Error occurred: {result.stderr}")
    except FileNotFoundError:
        messagebox.showerror("Error", "The fingerprint_capture.exe file was not found.")
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {e}")

def start_capture_thread():
    """Start fingerprint capture in a separate thread."""
    thread = threading.Thread(target=capture_fingerprint)
    thread.start()

# Create the Tkinter GUI
root = tk.Tk()
root.title("Fingerprint Capture")
root.geometry("300x150")

label = tk.Label(root, text="Fingerprint Capture System", font=("Arial", 14))
label.pack(pady=10)

capture_button = tk.Button(root, text="Capture Fingerprint", command=start_capture_thread, font=("Arial", 12))
capture_button.pack(pady=20)

root.mainloop()
