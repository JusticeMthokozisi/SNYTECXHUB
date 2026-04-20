#!/usr/bin/python3
import hashlib, os, sys, shutil, random, string
from getpass import getpass
from tabulate import tabulate
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class PasswordManager:
    def __init__(self):
        try:
            # Try to open existing database
            db_handle = open("passwords.db", "rb")
            self.path_to_database = "passwords.db"
        except FileNotFoundError:
            # Create or find database if not present
            self.path_to_database = self.check_database()
            db_handle = open(self.path_to_database, "rb")
        
        # Read the 64-char hash and the rest as ciphertext
        data = db_handle.read()
        db_handle.close()
        
        self.db_key_hash = data[:64].decode()
        self.ciphertext = data[64:]
        
        for _ in range(3):
            raw_key = getpass("Decryption key: ")
            self.decryption_key = self.pad_db_key(raw_key)
            if self.db_key_hash == hashlib.sha256(self.decryption_key.encode()).hexdigest():
                return self.decrypt_db()
            print("\U0000274C Invalid password")
        sys.exit()

    def decrypt_db(self):
        if self.ciphertext:
            try:
                aes = AES.new(self.decryption_key.encode(), AES.MODE_CBC, self.decryption_key[:16].encode())
                self.content = unpad(aes.decrypt(self.ciphertext), AES.block_size).decode("UTF-8")
                self.records_count = len(self.content.split("|")) if self.content else 0
                print(f"\U00002714 {self.records_count} records found")
            except Exception as e:
                print(f"\U0000274C Decryption failed: {e}")
                sys.exit()
        else:
            self.content, self.records_count = "", 0
            print("\U0001F5D1 Database has no records")
        self.display_options()

    def save_db(self):
        if self.records_count > 0 and self.content:
            aes = AES.new(self.decryption_key.encode(), AES.MODE_CBC, self.decryption_key[:16].encode())
            ct = aes.encrypt(pad(self.content.encode(), AES.block_size))
        else:
            ct = b""
        
        with open(self.path_to_database, "wb") as f:
            f.write(self.db_key_hash.encode() + ct)

    def check_database(self):
        print("> 'passwords.db' not found")
        p = input("> Enter absolute path or press Enter for new: ")
        full = os.path.join(p, "passwords.db") if p else "passwords.db"
        
        if os.path.exists(full): 
            return full
        
        # Create a new DB with default password
        default_pass = "password123"
        padded_default = self.pad_db_key(default_pass)
        db_hash = hashlib.sha256(padded_default.encode()).hexdigest()
        with open("passwords.db", "wb") as f: 
            f.write(db_hash.encode())
        
        print(f"Created new database. Default key: '{default_pass}'")
        return "passwords.db"

    def show_credentials(self):
        if not self.content or self.records_count == 0: 
            return print("\U0001F5D1 No records to show")
        
        # Parse the content string into a list of lists for tabulate
        table = [c.split("-") for c in self.content.split("|")]
        headers = ["ID", "User/Mail", "Password", "Platform"]
        
        print("\n" + tabulate(table, headers=headers, tablefmt="grid"))

    def add_credentials(self):
        u, p1, p2 = input("user/mail: "), input("pass: "), input("retype: ")
        if p1 != p2: return print("Mismatched \U0000274C")
        plat = input("platform: ")
        
        # Determine ID
        if self.records_count > 0:
            last_id = int(self.content.split("|")[-1].split("-")[0])
            rid = last_id + 1
        else:
            rid = 1
            
        new_entry = "-".join([str(rid), u, p1, plat])
        self.content = f"{self.content}|{new_entry}" if self.content else new_entry
        self.records_count += 1
        self.save_db()
        print("Added \U00002714")

    def edit_credentials(self):
        self.show_credentials()
        if not self.records_count: return
        try:
            rid = int(input("ID to edit: "))
            idx = self.find_record(rid)
            if idx is None: return print("\U0001F5D1 Not found")
            
            opt = int(input("[1] user [2] pass [3] platform\n> "))
            recs = [r.split("-") for r in self.content.split("|")]
            recs[idx][opt] = input("New value: ")
            
            self.content = "|".join(["-".join(r) for r in recs])
            self.save_db()
            print("\U00002714 Modified")
        except Exception as e: 
            print(f"\U0000274C Error: {e}")

    def delete_credentials(self):
        self.show_credentials()
        if not self.records_count: return
        try:
            rid = int(input("ID to delete: "))
            idx = self.find_record(rid)
            if idx is None: return
            
            recs = self.content.split("|")
            del recs[idx]
            self.records_count -= 1
            self.content = "|".join(recs) if recs else ""
            self.save_db()
            print("\U00002714 Deleted")
        except: 
            print("\U0000274C Error")

    def change_db_password(self):
        current = getpass("Current key: ")
        if hashlib.sha256(self.pad_db_key(current).encode()).hexdigest() != self.db_key_hash:
            return print("Wrong \U0000274C")
            
        n1, n2 = input("New key: "), input("Confirm: ")
        if n1 == n2 and len(n1) >= 8:
            self.decryption_key = self.pad_db_key(n1)
            self.db_key_hash = hashlib.sha256(self.decryption_key.encode()).hexdigest()
            self.save_db()
            print("\U00002714 Updated")
        else:
            print("\U0000274C Error (Mismatched or too short)")

    def generate_password(self):
        chars = string.ascii_letters + string.digits + string.punctuation
        print("Generated: " + "".join(random.choices(chars, k=24)))

    def backup_database(self):
        shutil.copyfile(self.path_to_database, self.path_to_database + ".bak")
        print(f"\U00002714 Backup saved as {self.path_to_database}.bak")

    def erase_database(self):
        confirm = input("Are you sure? (y/n): ")
        if confirm.lower() == 'y':
            self.content, self.records_count = "", 0
            self.save_db()
            print("\U0001F5D1 Erased")

    def pad_db_key(self, p):
        # AES keys must be 16, 24, or 32 bytes
        return p if len(p) % 16 == 0 else p + ("0" * (16 - (len(p) % 16)))

    def find_record(self, rid):
        recs = [r.split("-") for r in self.content.split("|")]
        for i, r in enumerate(recs):
            if int(r[0]) == rid: return i
        return None

    def display_options(self):
        opts = {
            1: self.show_credentials, 2: self.add_credentials, 
            3: self.edit_credentials, 4: self.delete_credentials, 
            5: self.change_db_password, 6: self.generate_password, 
            7: self.backup_database, 8: self.erase_database
        }
        while True:
            print("\n--- MENU ---")
            print("[1]Show [2]Add [3]Edit [4]Del [5]Pass [6]Gen [7]Bak [8]Erase [9]Exit")
            try:
                o = int(input("> "))
                if o == 9: 
                    print("\U0001F44B Goodbye")
                    break
                opts.get(o, lambda: print("\U0000274C Invalid"))()
            except ValueError:
                print("\U0000274C Please enter a number")
            except Exception as e:
                print(f"\nAn error occurred: {e}")
                break

if __name__ == "__main__":
    PasswordManager()