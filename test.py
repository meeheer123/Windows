import tkinter as tk
from tkinter import messagebox
import subprocess
import threading


def capture_fingerprint(prn, name, status_label):
    """Run the C++ fingerprint capture executable with provided PRN and name."""
    try:
        status_label.config(text="Status: Capturing fingerprint, please wait...")
        # Example: Pass PRN and name as command-line arguments to the executable
        result = subprocess.run([
            "fingerprint_app.exe",
            prn,
            name
        ], capture_output=True, text=True)

        if result.returncode == 0:
            messagebox.showinfo("Success", "Fingerprint captured and saved successfully!")
            status_label.config(text="Status: Fingerprint captured successfully.")
        else:
            messagebox.showerror("Error", f"Error occurred: {result.stderr}")
            status_label.config(text="Status: Error occurred during capture.")
    except FileNotFoundError:
        messagebox.showerror("Error", "The fingerprint_app.exe file was not found.")
        status_label.config(text="Status: Capture file not found.")
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {e}")
        status_label.config(text="Status: Unexpected error occurred.")


def open_capture_dialog(status_label):
    """Open a dialog to get PRN and name before capturing the fingerprint."""
    dialog = tk.Toplevel()
    dialog.title("Capture Fingerprint")
    dialog.geometry("300x200")
    dialog.resizable(False, False)

    tk.Label(dialog, text="Enter PRN:", font=("Arial", 12)).pack(pady=5)
    prn_entry = tk.Entry(dialog, font=("Arial", 12))
    prn_entry.pack(pady=5)

    tk.Label(dialog, text="Enter Name:", font=("Arial", 12)).pack(pady=5)
    name_entry = tk.Entry(dialog, font=("Arial", 12))
    name_entry.pack(pady=5)

    def on_scan():
        prn = prn_entry.get().strip()
        name = name_entry.get().strip()
        if not prn or not name:
            messagebox.showwarning("Input Error", "Please enter both PRN and Name.")
            return
        dialog.destroy()
        threading.Thread(target=capture_fingerprint, args=(prn, name, status_label)).start()

    scan_button = tk.Button(
        dialog,
        text="Scan",
        command=on_scan,
        font=("Arial", 12),
        bg="#4caf50",
        fg="white",
        activebackground="#45a049",
        activeforeground="white",
        width=10,
        height=1
    )
    scan_button.pack(pady=10)


def verify_fingerprint(status_label):
    """Run the C++ fingerprint verification executable."""
    try:
        status_label.config(text="Status: Verifying fingerprint, please wait...")
        result = subprocess.run(["verify_fingerprint_app.exe"], capture_output=True, text=True)
        if result.returncode == 0:
            messagebox.showinfo("Success", "Fingerprint verified successfully!")
            status_label.config(text="Status: Fingerprint verified successfully.")
        else:
            messagebox.showerror("Error", f"Error occurred: {result.stderr}")
            status_label.config(text="Status: Error occurred during verification.")
    except FileNotFoundError:
        messagebox.showerror("Error", "The verify_fingerprint_app.exe file was not found.")
        status_label.config(text="Status: Verification file not found.")
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {e}")
        status_label.config(text="Status: Unexpected error occurred.")


def start_thread(target, status_label):
    """Start a function in a separate thread."""
    thread = threading.Thread(target=target, args=(status_label,))
    thread.start()


def center_window(window, width, height):
    """Center the window on the screen."""
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width - width) // 2
    y = (screen_height - height) // 2
    window.geometry(f"{width}x{height}+{x}+{y}")


# Create the Tkinter GUI
root = tk.Tk()
root.title("Fingerprint System")
center_window(root, 400, 220)
root.resizable(False, False)

# Styling
root.configure(bg="#f0f0f5")

header = tk.Label(root, text="Fingerprint Capture System", font=("Arial", 16, "bold"), bg="#f0f0f5", fg="#333")
header.pack(pady=10)

status_label = tk.Label(root, text="Status: Ready", font=("Arial", 10), bg="#f0f0f5", fg="#555")
status_label.pack(pady=5)

button_frame = tk.Frame(root, bg="#f0f0f5")
button_frame.pack(pady=20)

capture_button = tk.Button(
    button_frame,
    text="Capture Fingerprint",
    command=lambda: open_capture_dialog(status_label),
    font=("Arial", 12),
    bg="#4caf50",
    fg="white",
    activebackground="#45a049",
    activeforeground="white",
    width=18,
    height=1
)
capture_button.grid(row=0, column=0, padx=10, pady=10)

verify_button = tk.Button(
    button_frame,
    text="Verify Fingerprint",
    command=lambda: start_thread(verify_fingerprint, status_label),
    font=("Arial", 12),
    bg="#2196f3",
    fg="white",
    activebackground="#1e88e5",
    activeforeground="white",
    width=18,
    height=1
)
verify_button.grid(row=0, column=1, padx=10, pady=10)

root.mainloop()
