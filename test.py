import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import subprocess
import threading
from datetime import datetime
import sqlite3
import os
import json
from tkinter import filedialog
import csv

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
            verification_timestamps TEXT DEFAULT '[]',
            isadmin INTEGER
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
            "INSERT INTO users (prn, name, fingerprint_file, fingerprint_data, isadmin) VALUES (?, ?, ?, ?, 0)",
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

def check_admin(status_label):
    """
    Verify fingerprint and check if the user has admin privileges.
    If admin, show attendance dialog; if not, show appropriate message.
    
    Args:
        status_label: tkinter Label widget for displaying status messages
    """
    try:
        status_label.config(text="Status: Verifying fingerprint, please wait...")
        isadmin = verify_fingerprint_in_db(status_label)
        
        if isadmin:
            show_attendance_dialog()
        else:
            messagebox.showinfo("Access Denied", "You need administrator privileges to view attendance records.")
            
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during verification: {str(e)}")
        status_label.config(text="Status: Verification error occurred.")
        
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
        cursor.execute("SELECT prn, name, fingerprint_data, verification_timestamps, isadmin FROM users")
        users = cursor.fetchall()

        match_found = False
        isadmin = False

        for user in users:
            stored_prn, stored_name, stored_fingerprint_data, timestamps_json, stored_admin_status = user
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
                if stored_admin_status == 1:
                    isadmin = True
                    return True
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
    from tkcalendar import DateEntry
    from datetime import datetime
    
    def export_to_csv(records):
        """Export the attendance records to a CSV file."""
        try:
            file_path = tk.filedialog.asksaveasfilename(
                defaultextension='.csv',
                filetypes=[("CSV files", '*.csv')],
                title="Export Attendance Records"
            )
            
            if file_path:
                with open(file_path, 'w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(["PRN", "Name", "Timestamp"])  # Header
                    writer.writerows(records)
                messagebox.showinfo("Success", "Records exported successfully!")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export records: {str(e)}")

    def display_records(records):
        """Display attendance records in a new window with sorting and export capabilities."""
        records_window = tk.Toplevel()
        records_window.title("Attendance Records")
        records_window.state('zoomed')

        # Create main container
        main_frame = ttk.Frame(records_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header frame
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 20))

        # Title
        title_label = ttk.Label(
            header_frame,
            text=f"Attendance Records ({len(records)} entries found)",
            font=("Arial", 16, "bold")
        )
        title_label.pack(side=tk.LEFT)

        # Export button
        export_button = ttk.Button(
            header_frame,
            text="Export to CSV",
            command=lambda: export_to_csv(records),
            style="Action.TButton",
            padding=10
        )
        export_button.pack(side=tk.RIGHT)

        # Create tree view with scrollbars
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        # Scrollbars
        y_scrollbar = ttk.Scrollbar(tree_frame)
        y_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        x_scrollbar = ttk.Scrollbar(tree_frame, orient='horizontal')
        x_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)

        # Treeview
        columns = ("PRN", "Name", "Timestamp")
        tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            yscrollcommand=y_scrollbar.set,
            xscrollcommand=x_scrollbar.set
        )

        # Configure scrollbars
        y_scrollbar.config(command=tree.yview)
        x_scrollbar.config(command=tree.xview)

        # Configure column headings
        for col in columns:
            tree.heading(col, text=col, command=lambda c=col: sort_treeview(tree, c, False))
            tree.column(col, minwidth=100, width=200)

        # Insert records
        for record in records:
            tree.insert("", tk.END, values=record)

        tree.pack(fill=tk.BOTH, expand=True)

        # Sorting function
        def sort_treeview(tree, col, reverse):
            """Sort treeview by column."""
            l = [(tree.set(k, col), k) for k in tree.get_children('')]
            l.sort(reverse=reverse)

            # Rearrange items in sorted positions
            for index, (val, k) in enumerate(l):
                tree.move(k, '', index)

            # Reverse sort next time
            tree.heading(col, command=lambda: sort_treeview(tree, col, not reverse))

    def fetch_attendance():
        """Fetch and display attendance records based on the date and time range."""
        try:
            # Get the date from calendar widgets
            start_date = start_date_cal.get_date()
            end_date = end_date_cal.get_date()
            
            # Get time from spinboxes
            start_time = f"{start_hour.get()}:{start_minute.get()}:{start_second.get()}"
            end_time = f"{end_hour.get()}:{end_minute.get()}:{end_second.get()}"
            
            # Combine date and time
            start_datetime = f"{start_date.strftime('%Y-%m-%d')} {start_time}"
            end_datetime = f"{end_date.strftime('%Y-%m-%d')} {end_time}"
            
            # Convert to datetime objects for validation
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
                
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")

    dialog = tk.Toplevel()
    dialog.title("View Attendance")
    dialog.geometry("800x600")
    
    # Main container with padding
    main_frame = ttk.Frame(dialog, padding="20")
    main_frame.pack(fill=tk.BOTH, expand=True)
    
    # Title
    title_label = ttk.Label(
        main_frame, 
        text="Attendance Record Search", 
        font=("Arial", 20, "bold")
    )
    title_label.pack(pady=(0, 20))
    
    # Create frames for start and end date-time
    start_frame = ttk.LabelFrame(main_frame, text="Start Date and Time", padding="10")
    start_frame.pack(fill=tk.X, padx=20, pady=10)
    
    end_frame = ttk.LabelFrame(main_frame, text="End Date and Time", padding="10")
    end_frame.pack(fill=tk.X, padx=20, pady=10)
    
    # Start date-time widgets
    ttk.Label(start_frame, text="Date:").grid(row=0, column=0, padx=5, pady=5)
    start_date_cal = DateEntry(
        start_frame,
        width=20,
        background='darkblue',
        foreground='white',
        borderwidth=2,
        date_pattern='yyyy-mm-dd'
    )
    start_date_cal.grid(row=0, column=1, padx=5, pady=5)
    
    ttk.Label(start_frame, text="Time:").grid(row=0, column=2, padx=5, pady=5)
    
    # Time spinboxes for start
    time_frame_start = ttk.Frame(start_frame)
    time_frame_start.grid(row=0, column=3, padx=5, pady=5)
    
    start_hour = ttk.Spinbox(time_frame_start, from_=0, to=23, width=3, format="%02.0f")
    start_hour.set("00")
    start_hour.pack(side=tk.LEFT)
    
    ttk.Label(time_frame_start, text=":").pack(side=tk.LEFT)
    
    start_minute = ttk.Spinbox(time_frame_start, from_=0, to=59, width=3, format="%02.0f")
    start_minute.set("00")
    start_minute.pack(side=tk.LEFT)
    
    ttk.Label(time_frame_start, text=":").pack(side=tk.LEFT)
    
    start_second = ttk.Spinbox(time_frame_start, from_=0, to=59, width=3, format="%02.0f")
    start_second.set("00")
    start_second.pack(side=tk.LEFT)
    
    # End date-time widgets
    ttk.Label(end_frame, text="Date:").grid(row=0, column=0, padx=5, pady=5)
    end_date_cal = DateEntry(
        end_frame,
        width=20,
        background='darkblue',
        foreground='white',
        borderwidth=2,
        date_pattern='yyyy-mm-dd'
    )
    end_date_cal.grid(row=0, column=1, padx=5, pady=5)
    
    ttk.Label(end_frame, text="Time:").grid(row=0, column=2, padx=5, pady=5)
    
    # Time spinboxes for end
    time_frame_end = ttk.Frame(end_frame)
    time_frame_end.grid(row=0, column=3, padx=5, pady=5)
    
    end_hour = ttk.Spinbox(time_frame_end, from_=0, to=23, width=3, format="%02.0f")
    end_hour.set("23")
    end_hour.pack(side=tk.LEFT)
    
    ttk.Label(time_frame_end, text=":").pack(side=tk.LEFT)
    
    end_minute = ttk.Spinbox(time_frame_end, from_=0, to=59, width=3, format="%02.0f")
    end_minute.set("59")
    end_minute.pack(side=tk.LEFT)
    
    ttk.Label(time_frame_end, text=":").pack(side=tk.LEFT)
    
    end_second = ttk.Spinbox(time_frame_end, from_=0, to=59, width=3, format="%02.0f")
    end_second.set("59")
    end_second.pack(side=tk.LEFT)
    
    # Fetch button
    fetch_button = ttk.Button(
        main_frame,
        text="Search Records",
        command=fetch_attendance,
        style="Accent.TButton",
        padding=10
    )
    fetch_button.pack(pady=20)
    
    # Create custom style for the button
    style = ttk.Style()
    style.configure(
        "Accent.TButton",
        font=("Arial", 12)
    )
    style.configure(
        "Action.TButton",
        font=("Arial", 11)
    )

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
    text="Mark Attendance",
    command=lambda: threading.Thread(target=verify_fingerprint_in_db, args=(status_label,)).start(),
    font=("Arial", 16),
    bg="#1395bd",
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
    command=lambda: threading.Thread(target=check_admin, args=(status_label,)).start(),
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
