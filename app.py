from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
import tkinter as tk
from tkinter import filedialog, messagebox
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
import threading

# Define color scheme
BACKGROUND_COLOR = "#FFFFFF"
TEXT_COLOR = "#333333"
BUTTON_COLOR = "#2979FF"
BUTTON_TEXT_COLOR = "#FFFFFF"
RELIEF_STYLE = tk.RAISED

# Define font styles
TITLE_FONT = ("Arial", 14, "bold")
LABEL_FONT = ("Arial", 10, "bold")
TEXT_FONT = ("Arial", 10)

# Define window dimensions
WINDOW_WIDTH = 500
WINDOW_HEIGHT = 600

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def save_key_to_file(key, filename):
    with open(filename, "wb") as file:
        file.write(key)

def load_key_from_file(filename):
    with open(filename, "rb") as file:
        key = file.read()
    return key

def encrypt_text(public_key, plaintext):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_v1_5.new(rsa_key)
    ciphertext = cipher_rsa.encrypt(plaintext.encode())
    encoded_ciphertext = base64.b64encode(ciphertext)
    return encoded_ciphertext.decode()

def decrypt_text(private_key, encoded_ciphertext):
    try:
        rsa_key = RSA.import_key(private_key)
        cipher_rsa = PKCS1_v1_5.new(rsa_key)
        ciphertext = base64.b64decode(encoded_ciphertext)
        plaintext = cipher_rsa.decrypt(ciphertext, None).decode()
        return plaintext
    except (ValueError, TypeError):
        messagebox.showerror("Decryption Error", "Invalid ciphertext or incorrect private key.")

def sign_text(private_key, plaintext):
    rsa_key = RSA.import_key(private_key)
    signer = pkcs1_15.new(rsa_key)
    hash_obj = SHA256.new(plaintext.encode())
    signature = signer.sign(hash_obj)
    encoded_signature = base64.b64encode(signature)
    return encoded_signature.decode()

def verify_signature(public_key, plaintext, encoded_signature):
    rsa_key = RSA.import_key(public_key)
    verifier = pkcs1_15.new(rsa_key)
    hash_obj = SHA256.new(plaintext.encode())
    signature = base64.b64decode(encoded_signature)
    try:
        verifier.verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False

def encrypt_file(public_key, input_filename, output_filename):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_v1_5.new(rsa_key)

    with open(input_filename, "rb") as input_file:
        plaintext = input_file.read()

    ciphertext = cipher_rsa.encrypt(plaintext)

    with open(output_filename, "wb") as output_file:
        output_file.write(ciphertext)

def decrypt_file(private_key, input_filename, output_filename):
    try:
        rsa_key = RSA.import_key(private_key)
        cipher_rsa = PKCS1_v1_5.new(rsa_key)

        with open(input_filename, "rb") as input_file:
            ciphertext = input_file.read()

        plaintext = cipher_rsa.decrypt(ciphertext, None)

        with open(output_filename, "wb") as output_file:
            output_file.write(plaintext)
    except (ValueError, TypeError):
        messagebox.showerror("Decryption Error", "Invalid ciphertext or incorrect private key.")

def sign_file(private_key, input_filename, signature_filename):
    rsa_key = RSA.import_key(private_key)
    signer = pkcs1_15.new(rsa_key)
    hash_obj = SHA256.new()

    with open(input_filename, "rb") as input_file:
        while True:
            chunk = input_file.read(1024)
            if not chunk:
                break
            hash_obj.update(chunk)

    signature = signer.sign(hash_obj)
    with open(signature_filename, "wb") as signature_file:
        signature_file.write(signature)

def verify_file_signature(public_key, input_filename, signature_filename):
    rsa_key = RSA.import_key(public_key)
    verifier = pkcs1_15.new(rsa_key)
    hash_obj = SHA256.new()

    with open(input_filename, "rb") as input_file:
        while True:
            chunk = input_file.read(1024)
            if not chunk:
                break
            hash_obj.update(chunk)

    with open(signature_filename, "rb") as signature_file:
        signature = signature_file.read()

    try:
        verifier.verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False

def select_file():
    file_path = filedialog.askopenfilename()
    return file_path

def select_save_location():
    file_path = filedialog.asksaveasfilename()
    return file_path

def send_email_with_attachment(sender_email, sender_password, recipient_email, subject, body, attachment_path):
    # Setup email message
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = recipient_email
    message["Subject"] = subject

    # Add email body
    message.attach(MIMEText(body, "plain"))

    # Add file attachment
    attachment = open(attachment_path, "rb")
    part = MIMEBase("application", "octet-stream")
    part.set_payload((attachment).read())
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", 'attachment; filename= "{}"'.format(os.path.basename(attachment_path)))
    message.attach(part)

    # Send email using SMTP with STARTTLS encryption
    with smtplib.SMTP("to be changed", 587) as server:
        server.starttls()  # Enable STARTTLS encryption
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, message.as_string())

def generate_keys_gui():
    private_key, public_key = generate_keys()
    private_key_text.configure(state="normal")
    private_key_text.delete("1.0", tk.END)
    private_key_text.insert(tk.END, private_key.decode())
    private_key_text.configure(state="disabled")
    public_key_text.configure(state="normal")
    public_key_text.delete("1.0", tk.END)
    public_key_text.insert(tk.END, public_key.decode())
    public_key_text.configure(state="disabled")
    messagebox.showinfo("Key Generation", "RSA keys generated successfully.")

def encrypt_text_gui():
    plaintext = text_input.get("1.0", tk.END).strip()
    if plaintext:
        encoded_ciphertext = encrypt_text(public_key, plaintext)
        text_output.delete("1.0", tk.END)
        text_output.insert(tk.END, encoded_ciphertext)
    else:
        messagebox.showerror("Encryption Error", "Please enter some text to encrypt.")

def decrypt_text_gui():
    encoded_ciphertext = text_input.get("1.0", tk.END).strip()
    if encoded_ciphertext:
        decrypted_text = decrypt_text(private_key, encoded_ciphertext)
        text_output.delete("1.0", tk.END)
        if decrypted_text is not None:
            text_output.insert(tk.END, decrypted_text)
    else:
        messagebox.showerror("Decryption Error", "Please enter some text to decrypt.")

def sign_text_gui():
    plaintext = text_input.get("1.0", tk.END).strip()
    if plaintext:
        encoded_signature = sign_text(private_key, plaintext)
        signature_output.delete("1.0", tk.END)
        signature_output.insert(tk.END, encoded_signature)
    else:
        messagebox.showerror("Signing Error", "Please enter some text to sign.")

def verify_signature_gui():
    plaintext = text_input.get("1.0", tk.END).strip()
    encoded_signature = signature_output.get("1.0", tk.END).strip()
    if plaintext and encoded_signature:
        valid_signature = verify_signature(public_key, plaintext, encoded_signature)
        if valid_signature:
            messagebox.showinfo("Signature Verification", "The signature is valid.")
        else:
            messagebox.showerror("Signature Verification", "The signature is invalid.")
    else:
        messagebox.showerror("Verification Error", "Please enter some text and a signature to verify.")

def encrypt_file_gui():
    input_file = select_file()
    if input_file:
        # Send the original file via email
        sender_email = "to be changed"  # Replace with your email address
        sender_password = "to be changed"  # Replace with your email password
        recipient_email = "to be changed"  # Replace with the recipient's email address
        subject = "Original File"
        body = "Please find the original file attached."

        # Send the email with the original file in a separate thread
        email_thread = threading.Thread(target=send_email_with_attachment, args=(sender_email, sender_password, recipient_email, subject, body, input_file))
        email_thread.start()

        # Encrypt the file
        # Generate output file path
        input_filename = os.path.basename(input_file)
        output_filename = "encrypted_" + input_filename

        encrypt_file(public_key, input_file, output_filename)
        messagebox.showinfo("File Encryption", "File encrypted successfully.")

    else:
        messagebox.showerror("File Encryption", "No input file selected.")


def decrypt_file_gui():
    input_file = select_file()
    if input_file:
        # Generate output file path
        input_filename = os.path.basename(input_file)
        output_filename = "decrypted_" + input_filename

        output_file_path = os.path.join(os.path.dirname(input_file), output_filename)
        decrypt_file(private_key, input_file, output_file_path)
        messagebox.showinfo("File Decryption", f"File decrypted successfully.\nDecrypted file saved as: {output_file_path}")
    else:
        messagebox.showerror("File Decryption", "No input file selected.")


def sign_file_gui():
    input_file = select_file()
    if input_file:
        # Generate output file path
        input_filename = os.path.basename(input_file)
        output_filename = "signed_" + input_filename

        # Sign the file
        sign_file(private_key, input_file, output_filename)
        messagebox.showinfo("File Signing", "File signed successfully.\nSigned file saved as: {}".format(output_filename))
    else:
        messagebox.showerror("File Signing", "No input file selected.")


def verify_file_signature_gui():
    input_file = select_file()
    if input_file:
        signature_file = select_file()  # Select the signature file
        if signature_file:
            # Verify the file signature
            valid_signature = verify_file_signature(public_key, input_file, signature_file)

            if valid_signature:
                messagebox.showinfo("Signature Verification", "The signature is valid.")
            else:
                messagebox.showerror("Signature Verification", "The signature is invalid.")
        else:
            messagebox.showerror("Signature Verification", "No signature file selected.")
    else:
        messagebox.showerror("Signature Verification", "No input file selected.")



# Generate and save the keys
private_key, public_key = generate_keys()
save_key_to_file(private_key, "private_key.pem")
save_key_to_file(public_key, "public_key.pem")

# Create the GUI
window = tk.Tk()
window.title("RSA Encryption Tool")
window.configure(background=BACKGROUND_COLOR)

# Set window dimensions
window_width = 500
window_height = 750
screen_width = window.winfo_screenwidth()
screen_height = window.winfo_screenheight()
x = (screen_width // 2) - (window_width // 2)
y = (screen_height // 2) - (window_height // 2)
window.geometry(f"{window_width}x{window_height}+{x}+{y}")


# Generate keys button
generate_keys_button = tk.Button(
    window,
    text="Generate Keys",
    font=LABEL_FONT,
    command=generate_keys_gui,
    bg=BUTTON_COLOR,
    fg=BUTTON_TEXT_COLOR,
    relief=RELIEF_STYLE,
)
generate_keys_button.pack(pady=20)

# Key display frames
keys_frame = tk.Frame(window, bg=BACKGROUND_COLOR)
keys_frame.pack()

# Public key display area
public_key_frame = tk.Frame(keys_frame, bg=BACKGROUND_COLOR)
public_key_frame.pack(side=tk.LEFT, padx=10, pady=10)
public_key_label = tk.Label(public_key_frame, text="Public Key:", font=LABEL_FONT, bg=BACKGROUND_COLOR, fg=TEXT_COLOR)
public_key_label.pack()
public_key_text = tk.Text(public_key_frame, height=8, width=35, font=TEXT_FONT, relief=RELIEF_STYLE)
public_key_text.insert(tk.END, public_key.decode())
public_key_text.configure(state=tk.DISABLED)
public_key_text.pack()

# Private key display area
private_key_frame = tk.Frame(keys_frame, bg=BACKGROUND_COLOR)
private_key_frame.pack(side=tk.LEFT, padx=10, pady=10)
private_key_label = tk.Label(private_key_frame, text="Private Key:", font=LABEL_FONT, bg=BACKGROUND_COLOR, fg=TEXT_COLOR)
private_key_label.pack()
private_key_text = tk.Text(private_key_frame, height=8, width=35, font=TEXT_FONT, relief=RELIEF_STYLE)
private_key_text.insert(tk.END, private_key.decode())
private_key_text.configure(state=tk.DISABLED)
private_key_text.pack()

# Text input area
text_input_frame = tk.Frame(window, bg=BACKGROUND_COLOR)
text_input_frame.pack(pady=20)
text_input_label = tk.Label(text_input_frame, text="Enter text:", font=LABEL_FONT, bg=BACKGROUND_COLOR, fg=TEXT_COLOR)
text_input_label.pack()
text_input = tk.Text(text_input_frame, height=5, width=50, font=TEXT_FONT, relief=RELIEF_STYLE)
text_input.pack()

# Text output area
text_output_frame = tk.Frame(window, bg=BACKGROUND_COLOR)
text_output_frame.pack(pady=10)
text_output_label = tk.Label(text_output_frame, text="Output:", font=LABEL_FONT, bg=BACKGROUND_COLOR, fg=TEXT_COLOR)
text_output_label.pack()
text_output = tk.Text(text_output_frame, height=5, width=50, font=TEXT_FONT, relief=RELIEF_STYLE)
text_output.pack()

# Signature output area
signature_output_frame = tk.Frame(window, bg=BACKGROUND_COLOR)
signature_output_frame.pack(pady=10)
signature_output_label = tk.Label(signature_output_frame, text="Signature:", font=LABEL_FONT, bg=BACKGROUND_COLOR, fg=TEXT_COLOR)
signature_output_label.pack()
signature_output = tk.Text(signature_output_frame, height=5, width=50, font=TEXT_FONT, relief=RELIEF_STYLE)
signature_output.pack()

# Text buttons line 1
text_buttons_line1_frame = tk.Frame(window, bg=BACKGROUND_COLOR)
text_buttons_line1_frame.pack()

# Encrypt text button
encrypt_text_button = tk.Button(
    text_buttons_line1_frame,
    text="Encrypt Text",
    font=LABEL_FONT,
    command=encrypt_text_gui,
    bg=BUTTON_COLOR,
    fg=BUTTON_TEXT_COLOR,
    relief=RELIEF_STYLE,
)
encrypt_text_button.pack(side=tk.LEFT, padx=10, pady=10)

# Decrypt text button
decrypt_text_button = tk.Button(
    text_buttons_line1_frame,
    text="Decrypt Text",
    font=LABEL_FONT,
    command=decrypt_text_gui,
    bg=BUTTON_COLOR,
    fg=BUTTON_TEXT_COLOR,
    relief=RELIEF_STYLE,
)
decrypt_text_button.pack(side=tk.LEFT, padx=10, pady=10)

# Sign text button
sign_text_button = tk.Button(
    text_buttons_line1_frame,
    text="Sign Text",
    font=LABEL_FONT,
    command=sign_text_gui,
    bg=BUTTON_COLOR,
    fg=BUTTON_TEXT_COLOR,
    relief=RELIEF_STYLE,
)
sign_text_button.pack(side=tk.LEFT, padx=10, pady=10)

# Verify signature button
verify_signature_button = tk.Button(
    text_buttons_line1_frame,
    text="Verify Signature",
    font=LABEL_FONT,
    command=verify_signature_gui,
    bg=BUTTON_COLOR,
    fg=BUTTON_TEXT_COLOR,
    relief=RELIEF_STYLE,
)
verify_signature_button.pack(side=tk.LEFT, padx=10, pady=10)

# Text buttons line 2
text_buttons_line2_frame = tk.Frame(window, bg=BACKGROUND_COLOR)
text_buttons_line2_frame.pack()

# Encrypt file button
encrypt_file_button = tk.Button(
    text_buttons_line2_frame,
    text="Encrypt File",
    font=LABEL_FONT,
    command=encrypt_file_gui,
    bg=BUTTON_COLOR,
    fg=BUTTON_TEXT_COLOR,
    relief=RELIEF_STYLE,
)
encrypt_file_button.pack(side=tk.LEFT, padx=10, pady=10)

# Decrypt file button
decrypt_file_button = tk.Button(
    text_buttons_line2_frame,
    text="Decrypt File",
    font=LABEL_FONT,
    command=decrypt_file_gui,
    bg=BUTTON_COLOR,
    fg=BUTTON_TEXT_COLOR,
    relief=RELIEF_STYLE,
)
decrypt_file_button.pack(side=tk.LEFT, padx=10, pady=10)

# Sign file button
sign_file_button = tk.Button(
    text_buttons_line2_frame,
    text="Sign File",
    font=LABEL_FONT,
    command=sign_file_gui,
    bg=BUTTON_COLOR,
    fg=BUTTON_TEXT_COLOR,
    relief=RELIEF_STYLE,
)
sign_file_button.pack(side=tk.LEFT, padx=10, pady=10)

# Verify file signature button
verify_file_signature_button = tk.Button(
    text_buttons_line2_frame,
    text="Verify File Signature",
    font=LABEL_FONT,
    command=verify_file_signature_gui,
    bg=BUTTON_COLOR,
    fg=BUTTON_TEXT_COLOR,
    relief=RELIEF_STYLE,
)
verify_file_signature_button.pack(side=tk.LEFT, padx=10, pady=10)

# Run the application
window.mainloop()
