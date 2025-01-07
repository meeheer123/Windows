import tkinter as tk
from tkinter import messagebox
import subprocess
import threading
import sqlite3
import os

def initialize_database():
    """Initialize the SQLite database and create the necessary table."""
    conn = sqlite3.connect("fingerprint_data.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            prn TEXT PRIMARY KEY,
            name TEXT,
            fingerprint_file TEXT,
            fingerprint_data BLOB
        )
    ''')
    conn.commit()
    conn.close()

def save_to_database(prn, name, fingerprint_file):
    """Save user data and fingerprint file to the SQLite database."""
    try:
        # Read the fingerprint file as binary data
        with open(fingerprint_file, "rb") as file:
            fingerprint_data = file.read()

        conn = sqlite3.connect("fingerprint_data.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (prn, name, fingerprint_file, fingerprint_data) VALUES (?, ?, ?, ?)",
            (prn, name, fingerprint_file, fingerprint_data)
        )
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        messagebox.showerror("Database Error", "A user with this PRN already exists.")
    except FileNotFoundError:
        messagebox.showerror("File Error", f"The fingerprint file '{fingerprint_file}' was not found.")
    except Exception as e:
        messagebox.showerror("Database Error", f"An unexpected error occurred: {e}")

def capture_fingerprint(prn, name, status_label):
    """Run the C++ fingerprint capture executable with provided PRN and name."""
    try:
        status_label.config(text="Status: Capturing fingerprint, please wait...")
        fingerprint_file = f"fingerprint.fir"
        result = subprocess.run([
            "fingerprint_app.exe",
            prn,
            name,
            fingerprint_file
        ], capture_output=True, text=True)

        if result.returncode == 0:
            if os.path.exists(fingerprint_file):
                save_to_database(prn, name, fingerprint_file)
                messagebox.showinfo("Success", "Fingerprint captured and saved successfully!")
                status_label.config(text="Status: Fingerprint captured successfully.")
            else:
                raise FileNotFoundError(f"Expected fingerprint file not found: {fingerprint_file}")
        else:
            messagebox.showerror("Error", f"Error occurred: {result.stderr}")
            status_label.config(text="Status: Error occurred during capture.")
    except FileNotFoundError as e:
        messagebox.showerror("Error", str(e))
        status_label.config(text="Status: File not found.")
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

def blob_to_fir(blob_data, prn):
    """Convert BLOB data from the database to a .fir file."""
    try:
        filename = f"dataFingerprint.fir"
        with open(filename, "wb") as f:
            f.write(blob_data)
        print(f"Fingerprint data saved as {filename}.")
    except Exception as e:
        print(f"Error saving BLOB to FIR file: {e}")

def fir_to_blob(fir_file):
    """Convert a .fir file to BLOB data."""
    try:
        with open(fir_file, "rb") as f:
            blob_data = f.read()
        print(f"FIR file {fir_file} converted to BLOB.")
        return blob_data
    except Exception as e:
        print(f"Error reading FIR file: {e}")
        return None

def verify_fingerprint_in_db(status_label):
    """Capture a fingerprint and verify it against stored fingerprints in the database."""
    try:
        status_label.config(text="Status: Verifying fingerprint, please wait...")
        captured_file = "fingerprint.fir"  # This file should be captured by the capture program

        print("Running fingerprint capture...")
        result = subprocess.run([
            "fingerprint_app.exe", "capture", captured_file  # Adjust the executable name as needed
        ], capture_output=True, text=True)

        if result.returncode != 0:
            print(f"Error: {result.stderr}")
            raise FileNotFoundError("Failed to capture fingerprint.")

        if not os.path.exists(captured_file):
            print(f"Captured file not found: {captured_file}")
            raise FileNotFoundError(f"Failed to capture fingerprint, file not found: {captured_file}")

        # Read the captured fingerprint as binary data
        with open(captured_file, "rb") as file:
            captured_data = file.read()

        conn = sqlite3.connect("fingerprint_data.db")
        cursor = conn.cursor()
        cursor.execute("SELECT prn, name, fingerprint_data FROM users")
        users = cursor.fetchall()

        match_found = False

        for user in users:
            stored_prn, stored_name, stored_fingerprint_data = user
            # Convert the stored BLOB to a FIR file for comparison
            stored_fingerprint_file = f"dataFingerprint.fir"
            blob_to_fir(stored_fingerprint_data, stored_prn)

            # Call verify.exe to compare the two FIR files
            print(f"Comparing captured fingerprint with stored fingerprint for {stored_name}...")

            verify_result = subprocess.run([
                "verify.exe"
            ], capture_output=True, text=True)

            print(verify_result.returncode)

            if verify_result.returncode == 0:
                # Check the output for match result
                messagebox.showinfo("Verification Success", f"Fingerprint for {stored_name} (PRN: {stored_prn}) matched!")
                status_label.config(text=f"Status: Fingerprint matched for PRN: {stored_prn}.")
                match_found = True
                break  # Exit the loop when a match is found
            else:
                print(f"Error during verification: {verify_result.stderr}")

        if not match_found:
            # If no match was found in the database
            messagebox.showerror("Verification Failed", "No matching fingerprint found in the database.")
            status_label.config(text="Status: No matching fingerprint found.")
        
        conn.close()

    except FileNotFoundError as e:
        print(f"Error: {str(e)}")
        messagebox.showerror("Error", str(e))
        status_label.config(text="Status: Capture or stored file not found.")
    except Exception as e:
        print(f"Unexpected error: {e}")
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

# Initialize database
initialize_database()

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
    command=lambda: start_thread(verify_fingerprint_in_db, status_label),
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
