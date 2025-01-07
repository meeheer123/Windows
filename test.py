import subprocess
import os
import tkinter as tk
from tkinter import messagebox, filedialog


def call_fingerprint_capture(cpp_executable):
    """Calls the C++ fingerprint scanner executable."""
    try:
        print(f"Calling C++ executable: {cpp_executable}")
        result = subprocess.run(
            [cpp_executable], capture_output=True, text=True
        )

        if result.returncode != 0:
            messagebox.showerror("Error", f"Fingerprint scan failed with code {result.returncode}\n{result.stderr}")
            return None

        for line in result.stdout.splitlines():
            if line.startswith("Fingerprint data saved to"):
                fingerprint_file = line.split("to ")[1].strip()
                if os.path.exists(fingerprint_file):
                    return fingerprint_file

        messagebox.showerror("Error", "Fingerprint file not found in the output.")
        return None

    except FileNotFoundError:
        messagebox.showerror("Error", f"C++ executable '{cpp_executable}' not found!")
        return None
    except Exception as e:
        messagebox.showerror("Error", f"Unexpected error: {e}")
        return None


def process_fingerprint(file_path):
    """Processes the fingerprint file."""
    if not os.path.exists(file_path):
        messagebox.showerror("Error", f"File {file_path} does not exist!")
        return

    with open(file_path, "rb") as f:
        data = f.read()

    processed_file = file_path.replace(".fir", "_processed.txt")
    with open(processed_file, "w") as out:
        out.write(f"Processed data length: {len(data)} bytes\n")

    messagebox.showinfo("Success", f"Fingerprint data processed and saved to {processed_file}")


def start_fingerprint_scan():
    """Triggers the fingerprint scanning process."""
    cpp_executable = "fingerprint_app.exe"  # Change this to the path of your C++ executable
    fingerprint_file = call_fingerprint_capture(cpp_executable)
    if fingerprint_file:
        process_fingerprint(fingerprint_file)


def select_existing_fingerprint():
    """Opens a dialog to select and process an existing fingerprint file."""
    file_path = filedialog.askopenfilename(
        title="Select Fingerprint File",
        filetypes=[("Fingerprint Files", "*.fir"), ("All Files", "*.*")]
    )
    if file_path:
        process_fingerprint(file_path)


def create_gui():
    """Creates the Tkinter GUI."""
    root = tk.Tk()
    root.title("Fingerprint Scanner")
    root.geometry("400x300")

    title_label = tk.Label(root, text="Fingerprint Scanner", font=("Arial", 16))
    title_label.pack(pady=10)

    scan_button = tk.Button(
        root, text="Start Fingerprint Scan", command=start_fingerprint_scan, font=("Arial", 12)
    )
    scan_button.pack(pady=10)

    select_button = tk.Button(
        root, text="Process Existing Fingerprint File", command=select_existing_fingerprint, font=("Arial", 12)
    )
    select_button.pack(pady=10)

    quit_button = tk.Button(root, text="Quit", command=root.quit, font=("Arial", 12))
    quit_button.pack(pady=10)

    root.mainloop()


if __name__ == "__main__":
    create_gui()
