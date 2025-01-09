import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import subprocess
import threading
from datetime import datetime
import sqlite3
import os
import json


def initialize_database():
    """Initialize the SQLite database and create the necessary table."""
    conn = sqlite3.connect("fingerprint_data.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            prn TEXT PRIMARY KEY,
            name TEXT,
            fingerprint_file TEXT,
            fingerprint_data BLOB,
            verification_timestamps TEXT DEFAULT '[]'
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
            (prn.upper(), name, fingerprint_file, fingerprint_data)
        )
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        messagebox.showerror("Database Error", "A user with this PRN already exists.")
        return "already exists"
    except FileNotFoundError:
        messagebox.showerror("File Error", f"The fingerprint file '{fingerprint_file}' was not found.")
    except Exception as e:
        messagebox.showerror("Database Error", f"An unexpected error occurred: {e}")
    finally:
        # Ensure the connection is closed properly
        conn.close()

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
                res = save_to_database(prn, name, fingerprint_file)
                if res != "already exists":
                    messagebox.showinfo("Success", "Fingerprint captured and saved successfully!")
                    status_label.config(text="Status: Fingerprint captured successfully.")
                else:
                    status_label.config(text="Status: User with PRN already exists.")
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
    dialog.state('zoomed')  # Make the dialog fullscreen

    # Create a parent frame to center the content
    parent_frame = tk.Frame(dialog)
    parent_frame.pack(expand=True, fill=tk.BOTH)

    # Center the content vertically and horizontally
    content_frame = tk.Frame(parent_frame)
    content_frame.pack(expand=True)

    tk.Label(content_frame, text="Enter PRN:", font=("Arial", 16)).pack(pady=10)
    prn_entry = tk.Entry(content_frame, font=("Arial", 16), width=40)
    prn_entry.pack(pady=10)

    tk.Label(content_frame, text="Enter Name:", font=("Arial", 16)).pack(pady=10)
    name_entry = tk.Entry(content_frame, font=("Arial", 16), width=40)
    name_entry.pack(pady=10)

    def on_scan():
        prn = prn_entry.get().strip()
        name = name_entry.get().strip()
        if not prn or not name:
            messagebox.showwarning("Input Error", "Please enter both PRN and Name.")
            return
        dialog.destroy()
        threading.Thread(target=capture_fingerprint, args=(prn, name, status_label)).start()

    scan_button = tk.Button(
        content_frame,
        text="Scan",
        command=on_scan,
        font=("Arial", 16),
        bg="#4caf50",
        fg="white",
        activebackground="#45a049",
        activeforeground="white",
        width=20,
        height=2
    )
    scan_button.pack(pady=20)

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
        cursor.execute("SELECT prn, name, fingerprint_data, verification_timestamps FROM users")
        users = cursor.fetchall()

        match_found = False

        for user in users:
            stored_prn, stored_name, stored_fingerprint_data, timestamps_json = user
            timestamps = json.loads(timestamps_json) if timestamps_json else []

            # Convert the stored BLOB to a FIR file for comparison
            stored_fingerprint_file = f"dataFingerprint.fir"
            with open(stored_fingerprint_file, "wb") as f:
                f.write(stored_fingerprint_data)

            # Call verify.exe to compare the two FIR files
            print(f"Comparing captured fingerprint with stored fingerprint for {stored_name}...")

            verify_result = subprocess.run([
                "verify.exe"
            ], capture_output=True, text=True)

            if verify_result.returncode == 0:
                # Append the current timestamp to the verification timestamps
                current_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                timestamps.append(current_timestamp)

                # Update the timestamps in the database
                cursor.execute(
                    "UPDATE users SET verification_timestamps = ? WHERE prn = ?",
                    (json.dumps(timestamps), stored_prn)
                )
                conn.commit()
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

def show_attendance_dialog():
    """Open a dialog to input start and end dates for filtering attendance."""
    def fetch_attendance():
        """Fetch and display attendance records based on the date and time range."""
        try:
            start_datetime = start_date_entry.get().strip()
            end_datetime = end_date_entry.get().strip()

            if not start_datetime or not end_datetime:
                messagebox.showwarning("Input Error", "Please enter both start and end date-time.")
                return

            # Convert input to datetime objects for validation
            start_datetime_obj = datetime.strptime(start_datetime, "%Y-%m-%d %H:%M:%S")
            end_datetime_obj = datetime.strptime(end_datetime, "%Y-%m-%d %H:%M:%S")

            if start_datetime_obj > end_datetime_obj:
                messagebox.showerror("Date-Time Error", "Start date-time must be before or equal to end date-time.")
                return

            conn = sqlite3.connect("fingerprint_data.db")
            cursor = conn.cursor()
            cursor.execute("SELECT prn, name, verification_timestamps FROM users")
            users = cursor.fetchall()
            conn.close()

            records = []

            for user in users:
                prn, name, timestamps_json = user
                timestamps = json.loads(timestamps_json)
                for ts in timestamps:
                    ts_datetime = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                    if start_datetime_obj <= ts_datetime <= end_datetime_obj:
                        records.append((prn, name, ts))

            if records:
                display_records(records)
            else:
                messagebox.showinfo("No Records", "No attendance records found for the specified date-time range.")
        except ValueError as ve:
            messagebox.showerror("Input Error", "Please enter date-time in YYYY-MM-DD HH:MM:SS format.")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")

    def display_records(records):
        """Display attendance records in a new window."""
        records_window = tk.Toplevel()
        records_window.title("Attendance Records")
        records_window.state('zoomed')  # Make the window fullscreen

        columns = ("PRN", "Name", "Timestamp")

        tree = ttk.Treeview(records_window, columns=columns, show="headings")
        tree.heading("PRN", text="PRN")
        tree.heading("Name", text="Name")
        tree.heading("Timestamp", text="Timestamp")

        for record in records:
            tree.insert("", tk.END, values=record)

        tree.pack(fill=tk.BOTH, expand=True)

    dialog = tk.Toplevel()
    dialog.title("View Attendance")
    dialog.state('zoomed')  # Make the dialog fullscreen

    # Create a parent frame to center the content
    parent_frame = tk.Frame(dialog)
    parent_frame.pack(expand=True, fill=tk.BOTH)

    # Center the content vertically and horizontally
    content_frame = tk.Frame(parent_frame)
    content_frame.pack(expand=True)

    tk.Label(content_frame, text="Start Date-Time (YYYY-MM-DD HH:MM:SS):", font=("Arial", 14)).pack(pady=10)
    start_date_entry = tk.Entry(content_frame, font=("Arial", 14), width=40)
    start_date_entry.pack(pady=10)

    tk.Label(content_frame, text="End Date-Time (YYYY-MM-DD HH:MM:SS):", font=("Arial", 14)).pack(pady=10)
    end_date_entry = tk.Entry(content_frame, font=("Arial", 14), width=40)
    end_date_entry.pack(pady=10)

    fetch_button = tk.Button(
        content_frame,
        text="Fetch Records",
        command=fetch_attendance,
        font=("Arial", 14),
        bg="#2196f3",
        fg="white",
        activebackground="#1e88e5",
        activeforeground="white",
        width=20,
        height=2
    )
    fetch_button.pack(pady=20)

    # attendance_text = tk.Text(dialog, font=("Arial", 14), wrap=tk.WORD, width=80, height=20)
    # attendance_text.pack(pady=20)

def main():
    initialize_database()

root = tk.Tk()
root.title("Fingerprint Scanner")
root.state('zoomed')  # Make the main window fullscreen

# Parent frame to center content
parent_frame = tk.Frame(root)
parent_frame.pack(expand=True, fill=tk.BOTH)

# Content frame for actual widgets
content_frame = ttk.Frame(parent_frame, padding="30 30 30 30")
content_frame.pack(expand=True)

title_label = tk.Label(content_frame, text="Fingerprint Scanner", font=("Arial", 24, "bold"))
title_label.grid(row=0, column=0, columnspan=2, pady=20)

status_label = tk.Label(content_frame, text="Status: Idle", font=("Arial", 16))
status_label.grid(row=1, column=0, columnspan=2, pady=20)

capture_button = tk.Button(
    content_frame,
    text="Capture Fingerprint",
    command=lambda: open_capture_dialog(status_label),
    font=("Arial", 16),
    bg="#4caf50",
    fg="white",
    activebackground="#45a049",
    activeforeground="white",
    width=30,
    height=2
)
capture_button.grid(row=2, column=0,padx=10, pady=20)

verify_button = tk.Button(
    content_frame,
    text="Verify Fingerprint",
    command=lambda: threading.Thread(target=verify_fingerprint_in_db, args=(status_label,)).start(),
    font=("Arial", 16),
    bg="#4caf50",
    fg="white",
    activebackground="#45a049",
    activeforeground="white",
    width=30,
    height=2
)
verify_button.grid(row=2, column=1,padx=10, pady=20)

attendance_button = tk.Button(
    content_frame,
    text="View Attendance",
    command=show_attendance_dialog,
    font=("Arial", 16),
    bg="#4caf50",
    fg="white",
    activebackground="#45a049",
    activeforeground="white",
    width=30,
    height=2
)
attendance_button.grid(row=3, column=0, columnspan=2, pady=20)


root.mainloop()

if __name__ == "__main__":
    main()
