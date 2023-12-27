import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox, simpledialog
from PIL import Image, ImageTk
import json
import os
from cryptography.fernet import Fernet

class ImgLockApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ImgLock App")
        self.root.geometry("400x200")

        
        self.load_config_data()


        self.create_gui()

    def load_config_data(self):

        if os.path.exists("config.json"):
            with open("config.json", "r") as json_file:
                config_data = json.load(json_file)
                self.password = self.decrypt_password(config_data.get("password", ""))
        else:
        
            self.set_password_gui()
            self.save_config_data()

    def save_config_data(self):
        config_data = {"password": self.encrypt_password(self.password)}
        with open("config.json", "w") as json_file:
            json.dump(config_data, json_file)

    def encrypt_password(self, password):

        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        encrypted_password = cipher_suite.encrypt(password.encode())
        return {"key": key.decode(), "password": encrypted_password.decode()}

    def decrypt_password(self, encrypted_data):
        if encrypted_data:
            key = encrypted_data["key"].encode()
            cipher_suite = Fernet(key)
            decrypted_password = cipher_suite.decrypt(encrypted_data["password"].encode())
            return decrypted_password.decode()
        return ""

    def create_gui(self):

        home_label = tk.Label(self.root, text="ImgLock App", font=("Helvetica", 20, "bold"))
        home_label.pack(pady=20)

        encrypt_button = tk.Button(
            self.root, text="Make new ImgLock image", command=self.encrypt_image, font=("Helvetica", 12)
        )
        encrypt_button.pack(pady=15)


        decrypt_button = tk.Button(
            self.root, text="View ImgLock image", command=self.decrypt_image, font=("Helvetica", 12)
        )
        decrypt_button.pack(pady=15)

    def set_password_gui(self):
        password = simpledialog.askstring("Set Password", "Set a password:", show='*')

        while not password:

            messagebox.showwarning("Invalid Password", "Password cannot be empty. Please try again.")
            password = simpledialog.askstring("Set Password", "Set a password:", show='*')

        self.password = password

    def encrypt_image(self):
        file_path = filedialog.askopenfilename(title="Select an image", filetypes=[("Image files", "*.png;*.jpg")])

        if file_path:

            original_image = Image.open(file_path)

            encrypted_image = original_image.transpose(Image.FLIP_LEFT_RIGHT)


            encrypted_path = filedialog.asksaveasfilename(
                defaultextension=".imgLock", filetypes=[("ImgLock files", "*.imgLock")],
                initialfile="image" 
            )
            if encrypted_path:

                root, _ = os.path.splitext(encrypted_path)


                imglock_path = root + '.imgLock'
                with open(imglock_path, 'wb') as f:
                    encrypted_image.save(f, format='PNG')
                messagebox.showinfo("Success", f"Image encrypted and saved as {imglock_path}")

    def decrypt_image(self):
        entered_password = simpledialog.askstring("Password", "Enter the password:", show='*')

        if entered_password == self.password:
            file_path = filedialog.askopenfilename(title="Select an ImgLock image", filetypes=[("ImgLock files", "*.imgLock")])

            if file_path:

                encrypted_image = Image.open(file_path)


                decrypted_image = encrypted_image.transpose(Image.FLIP_LEFT_RIGHT)
                

               
                decrypted_image.show()
        else:
            messagebox.showwarning("Access Denied", "Incorrect password. Access denied.")

if __name__ == "__main__":
    root = tk.Tk()
    app = ImgLockApp(root)
    root.mainloop()
