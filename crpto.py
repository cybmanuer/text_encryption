import base64
from cryptography.fernet import Fernet
import rsa
from tkinter import *
from tkinter import messagebox

# Function to generate AES key and encrypt message
def aes_encrypt(message):
    key = Fernet.generate_key()
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return key.decode(), encrypted_message.decode()

# Function to decrypt AES encrypted message
def aes_decrypt(key, encrypted_message):
    fernet = Fernet(key.encode())
    decrypted_message = fernet.decrypt(encrypted_message.encode())
    return decrypted_message.decode()

def encrypt_text():
    message = input_text.get("1.0", END).strip()
    
    if not message:
        messagebox.showerror("Error", "Please enter text to encrypt.")
        return
    
    key, encrypted_message = aes_encrypt(message)
    output_text.delete("1.0", END)
    output_text.insert(END, f" AES Key: {key}\nEncrypted Message: {encrypted_message}")
    highlight_text(output_text, encrypted_message)

def decrypt_text():
    key = key_input.get().strip()
    encrypted_message = output_text.get("1.0", END).strip().split("\n")[1].split(": ")[1]
    
    try:
        decrypted_message = aes_decrypt(key, encrypted_message)
        output_text.insert(END, f"\n\n Decrypted Message : {decrypted_message}")
        highlight_text(output_text, decrypted_message)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def highlight_text(text_widget, decrypted_message):
    start_index = text_widget.search("Decrypted Message: ", "1.0", stopindex=END)
    if start_index:
        start_index = f"{start_index.split('.')[0]}.{len('Decrypted Message:') + 1}"
        end_index = f"{start_index.split('.')[0]}.{len(decrypted_message) + len('Decrypted Message:') + 1}"
        text_widget.tag_add("highlight", start_index, end_index)

# Main window setup
root = Tk()
root.title("SecureText Encryption")
root.geometry("600x500")
root.configure(bg="#f0f0f0")

# Header Label
header_label = Label(root, text="SecureText Encryption", font=("Helvetica", 16, "bold"), bg="#f0f0f0")
header_label.place(relx=0.5, y=10, anchor='n')

# Input Frame
input_frame = Frame(root, bg="#f0f0f0")
input_frame.pack(pady=10)

Label(input_frame, text="Enter Text To Encrypt", font=("Helvetica", 12, "bold"), bg="#f0f0f0").grid(row=0, column=0)
input_text = Text(input_frame, height=5, width=60, font=("Helvetica", 12))
input_text.grid(row=1, column=0)

Button(input_frame, text="Encrypt", command=encrypt_text, bg="#4A90E2", fg="white", font=("Helvetica", 12)).grid(row=2, column=0, pady=5)
Button(input_frame, text="Decrypt", command=decrypt_text, bg="#E94E77", fg="white", font=("Helvetica", 12)).grid(row=3, column=0, pady=10)

# Key Input Frame
key_frame = Frame(root, bg="#f0f0f0")
key_frame.pack(pady=10)

Label(key_frame, text="AES Key For Decryption", font=("Helvetica", 12, "bold"), bg="#f0f0f0").grid(row=0, column=0)
key_input = Entry(key_frame, width=60, font=("Helvetica", 12))
key_input.grid(row=1, column=0)

# Output Frame
output_frame = Frame(root, bg="#f0f0f0")
output_frame.pack(pady=10)

Label(output_frame, text="Output ", font=("Helvetica", 12, "bold"), bg="#f0f0f0").grid(row=0, column=0)
output_text = Text(output_frame, height=10, width=50, font=("Helvetica", 12))
output_text.grid(row=1, column=0)

# Highlighting tag configuration
output_text.tag_configure("highlight", background="yellow")

root.mainloop()
