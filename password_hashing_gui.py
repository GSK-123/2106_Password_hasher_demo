import tkinter as tk
from tkinter import ttk, messagebox
import pyperclip
import time
from argon2 import PasswordHasher
import bcrypt
from passlib.hash import pbkdf2_sha256

argon2_hasher = PasswordHasher()
latest_hash = ""


def hash_password():
    global latest_hash
    algorithm = algorithm_selection.get()
    password = password_entry.get()
    # if not password:
    #     messagebox.showerror("Error", "Please enter a password.")
    #     return

    start_time = time.time()
    try:
        if algorithm == "Argon2":
            memory_cost = int(argon2_memory.get())
            parallelism = int(argon2_parallelism.get())
            time_cost = int(argon2_time_cost.get())
            ph = PasswordHasher(memory_cost=memory_cost, parallelism=parallelism, time_cost=time_cost)
            latest_hash = ph.hash(password)
        elif algorithm == "bcrypt":
            rounds = int(bcrypt_rounds.get())
            salt = bcrypt.gensalt(rounds)
            latest_hash = bcrypt.hashpw(password.encode(), salt).decode()
        elif algorithm == "PBKDF2":
            iterations = int(pbkdf2_iterations.get())
            latest_hash = pbkdf2_sha256.using(rounds=iterations).hash(password)
        else:
            raise ValueError("Invalid algorithm selected.")
    except Exception as e:
        messagebox.showerror("Error", f"Hashing failed: {e}")
        return

    end_time = time.time()
    time_taken = end_time - start_time
    result_label.config(text=f"Hash: {latest_hash}\nTime: {time_taken:.4f}s")
    messagebox.showinfo("Hash Generated", f"Hash:\n{latest_hash}\n\nClick 'Copy' to save it to your clipboard.")


def copy_to_clipboard():
    if latest_hash:
        pyperclip.copy(latest_hash)
        messagebox.showinfo("Copied", "The hash has been copied to your clipboard.")
    else:
        messagebox.showerror("Error", "No hash available to copy.")


def verify_password():
    password = password_entry.get()
    stored_hash = hash_verification_entry.get()
    algorithm = algorithm_selection.get()

    # if not password or not stored_hash:
    #     messagebox.showerror("Error", "Please enter both password and hash.")
    #     return

    try:
        if algorithm == "Argon2":
            argon2_hasher.verify(stored_hash, password)
            messagebox.showinfo("Success", "Password matches the hash!")
        elif algorithm == "bcrypt":
            if bcrypt.checkpw(password.encode(), stored_hash.encode()):
                messagebox.showinfo("Success", "Password matches the hash!")
            else:
                raise ValueError("Password does not match.")
        elif algorithm == "PBKDF2":
            if pbkdf2_sha256.verify(password, stored_hash):
                messagebox.showinfo("Success", "Password matches the hash!")
            else:
                raise ValueError("Password does not match.")
        else:
            raise ValueError("Invalid algorithm selected.")
    except Exception as e:
        messagebox.showerror("Error", f"Verification failed: {e}")


def show_parameters(event):
    """Show parameter fields based on the selected algorithm."""
    algo = algorithm_selection.get()
    for widget in param_frame.winfo_children():
        widget.grid_forget()
    if algo == "Argon2":
        argon2_memory_label.grid(row=0, column=0)
        argon2_memory.grid(row=0, column=1)
        argon2_parallelism_label.grid(row=1, column=0)
        argon2_parallelism.grid(row=1, column=1)
        argon2_time_cost_label.grid(row=2, column=0)
        argon2_time_cost.grid(row=2, column=1)
    elif algo == "bcrypt":
        bcrypt_rounds_label.grid(row=0, column=0)
        bcrypt_rounds.grid(row=0, column=1)
    elif algo == "PBKDF2":
        pbkdf2_iterations_label.grid(row=0, column=0)
        pbkdf2_iterations.grid(row=0, column=1)
root = tk.Tk()
root.title("Password Hashing Demonstrator")
tk.Label(root, text="Enter Password:").grid(row=0, column=0, padx=10, pady=10)
password_entry = tk.Entry(root, show="*")
password_entry.grid(row=0, column=1, padx=10, pady=10)
tk.Label(root, text="Select Algorithm:").grid(row=1, column=0, padx=10, pady=10)
algorithm_selection = ttk.Combobox(root, values=["Argon2", "bcrypt", "PBKDF2"])
algorithm_selection.grid(row=1, column=1, padx=10, pady=10)
algorithm_selection.current(0)
param_frame = tk.Frame(root)
param_frame.grid(row=2, column=0, columnspan=2, pady=10)
argon2_memory_label = tk.Label(param_frame, text="Memory (KB):")
argon2_memory = tk.Entry(param_frame)
argon2_memory.insert(0, "65536")
argon2_parallelism_label = tk.Label(param_frame, text="Parallelism:")
argon2_parallelism = tk.Entry(param_frame)
argon2_parallelism.insert(0, "1")
argon2_time_cost_label = tk.Label(param_frame, text="Time Cost:")
argon2_time_cost = tk.Entry(param_frame)
argon2_time_cost.insert(0, "3")
bcrypt_rounds_label = tk.Label(param_frame, text="bcrypt Rounds:")
bcrypt_rounds = tk.Entry(param_frame)
bcrypt_rounds.insert(0, "12")
pbkdf2_iterations_label = tk.Label(param_frame, text="PBKDF2 Iterations:")
pbkdf2_iterations = tk.Entry(param_frame)
pbkdf2_iterations.insert(0, "100000")
hash_button = tk.Button(root, text="Hash Password", command=hash_password)
hash_button.grid(row=5, column=0, padx=10, pady=10)
result_label = tk.Label(root, text="Hash: \nTime:")
result_label.grid(row=5, column=1, padx=10, pady=10)
copy_button = tk.Button(root, text="Copy", command=copy_to_clipboard)
copy_button.grid(row=6, column=0, columnspan=2, pady=10)
tk.Label(root, text="Enter Hash for Verification:").grid(row=7, column=0, padx=10, pady=10)
hash_verification_entry = tk.Entry(root)
hash_verification_entry.grid(row=7, column=1, padx=10, pady=10)
verify_button = tk.Button(root, text="Verify Password", command=verify_password)
verify_button.grid(row=8, column=0, columnspan=2, pady=10)
algorithm_selection.bind("<<ComboboxSelected>>", show_parameters)
show_parameters(None)
root.mainloop()
