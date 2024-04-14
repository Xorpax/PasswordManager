import ast
import customtkinter
import customtkinter as ctk
import string
import secrets
from typing import Any
from Crypto.Cipher import AES
import hashlib
import configparser
import pandas
from PIL import Image
import pandas as pd
import sys
import os

# TODO: ADD AUTOMATIC SCREEN LOCKING USING AFTER METHOD
# TODO: ADD COLOR PICKERS AND PRIMARY, SECONDARY COLORS

BLUE = "#4c4c6d"
GREEN = "#1b9c85"
WHITE = "#e8f6ef"
YELLOW = "#ffe194"


# customtkinter.set_appearance_mode("system")  # default value
# customtkinter.set_appearance_mode("dark")
# customtkinter.set_appearance_mode("light")


def resource(relative_path):
    base_path = getattr(
        sys,
        '_MEIPASS',
        os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)


config = configparser.ConfigParser()
config.read("config.ini")

LOGINS_FILE: str | bytes = resource(config["FilePaths"]["LOGINS_FILE"])

DARK_MODE_DARK = resource(config["FilePaths"]["DARK_MODE_DARK"])
DARK_MODE_LIGHT = resource(config["FilePaths"]["DARK_MODE_LIGHT"])
LIGHT_MODE_DARK = resource(config["FilePaths"]["LIGHT_MODE_DARK"])
LIGHT_MODE_LIGHT = resource(config["FilePaths"]["LIGHT_MODE_LIGHT"])

LIGHT_GEAR = resource(config["FilePaths"]["LIGHT_GEAR"])
DARK_GEAR = resource(config["FilePaths"]["LIGHT_GEAR"])

LIGHT_SHOW_PWD = resource(config["FilePaths"]["LIGHT_SHOW_PWD"])
DARK_SHOW_PWD = resource(config["FilePaths"]["DARK_SHOW_PWD"])
LIGHT_HIDE_PWD = resource(config["FilePaths"]["LIGHT_HIDE_PWD"])
DARK_HIDE_PWD = resource(config["FilePaths"]["DARK_HIDE_PWD"])

MAIN_FONT_NAME = "Comic Sans MS"


LOGIN_ENTRY_OPTIONS = pandas.read_csv(LOGINS_FILE)["title"].tolist()


settings_image = ctk.CTkImage(light_image=Image.open(LIGHT_GEAR),
                              dark_image=Image.open(DARK_GEAR),
                              )

show_pwd = ctk.CTkImage(light_image=Image.open(LIGHT_SHOW_PWD),
                        dark_image=Image.open(DARK_SHOW_PWD),
                        )

hide_pwd = ctk.CTkImage(light_image=Image.open(LIGHT_HIDE_PWD),
                        dark_image=Image.open(DARK_HIDE_PWD),
                        )


def update_entry_list() -> None:
    global LOGIN_ENTRY_OPTIONS
    LOGIN_ENTRY_OPTIONS = pandas.read_csv(LOGINS_FILE)["title"].tolist()


def open_settings() -> None:
    """Instantiate a settings window and focus on it."""
    settings = Settings(app)
    settings.grab_set()


class FoldersFrame(ctk.CTkFrame):
    def __init__(self, *args, header_name="Passwords", **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.header_name = header_name

        self.header = ctk.CTkLabel(self, text=self.header_name, font=(MAIN_FONT_NAME, 20))
        self.header.pack(anchor=ctk.CENTER, pady=5)

        self.logins_menu = ctk.CTkOptionMenu(self,
                                             values=LOGIN_ENTRY_OPTIONS,
                                             command=self.load_entry,
                                             font=(MAIN_FONT_NAME, 12)
                                             )
        self.logins_menu.pack(anchor=ctk.CENTER, pady=10)

    def load_entry(self, val) -> None:
        """Populate entry widgets from saved logins."""
        global LOGIN_ENTRY_OPTIONS
        update_entry_list()
        self.logins_menu.configure(values=LOGIN_ENTRY_OPTIONS)
        app.load_password(title=val)


class PasswordPage(ctk.CTkCanvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.login_data = pandas.read_csv(LOGINS_FILE)

        # Main
        self.title_label = ctk.CTkLabel(self, text="Title", font=(MAIN_FONT_NAME, 30))
        self.create_window(210, 25, window=self.title_label)
        self.title_entry = ctk.CTkEntry(self, font=(MAIN_FONT_NAME, 13), placeholder_text="Title*")
        self.create_window(215, 74, window=self.title_entry, width=200, height=35)
        self.required_label = ctk.CTkLabel(self, text="* Required", font=(MAIN_FONT_NAME, 15, "bold"))
        self.create_window(156, 105, window=self.required_label)
        # login details
        self.login_details_label = ctk.CTkLabel(self, text="Login Details", font=(MAIN_FONT_NAME, 16, "bold"))
        self.create_window(167, 143, window=self.login_details_label)
        self.usr_name = ctk.CTkEntry(self, font=(MAIN_FONT_NAME, 13), placeholder_text="Email or Username")
        self.create_window(215, 175, window=self.usr_name, width=200, height=35)
        self.pwd = ctk.CTkEntry(self, font=(MAIN_FONT_NAME, 13), placeholder_text="Password", show="*")
        self.create_window(215, 214, window=self.pwd, width=200, height=35)
        self.show_pwd_btn = ctk.CTkButton(self,
                                          image=show_pwd,
                                          text="",
                                          width=33,
                                          height=33,
                                          fg_color="transparent",
                                          hover_color=GREEN,
                                          command=self.change_btn_img
                                          )
        self.create_window(340, 214, window=self.show_pwd_btn)
        self.pwd_btn_state = "show"

        # password generation
        self.generate_pwd = ctk.CTkButton(self,
                                          text="Generate Password",
                                          font=(MAIN_FONT_NAME, 13, "bold"),
                                          fg_color="transparent",
                                          hover=False,
                                          command=self.generate_password
                                          )
        self.create_window(177, 245, window=self.generate_pwd)
        # length
        self.len_label = ctk.CTkLabel(self, text="Length", font=(MAIN_FONT_NAME, 15, "bold"))
        self.create_window(142, 285, window=self.len_label)
        self.pword_len_slider = ctk.CTkSlider(self,
                                              from_=1,
                                              to=20,
                                              command=self.update_length,
                                              number_of_steps=20
                                              )
        self.create_window(210, 315, window=self.pword_len_slider, width=190)
        self.pword_len_slider.set(1)
        self.pword_length = str(int(self.pword_len_slider.get()))
        self.pword_len_label = ctk.CTkLabel(self, text=self.pword_length, font=(MAIN_FONT_NAME, 14, "bold"))
        self.create_window(320, 315, window=self.pword_len_label)
        # caps
        self.caps_switch = ctk.CTkSwitch(self,
                                         switch_width=35,
                                         switch_height=16,
                                         corner_radius=10,
                                         text="Capital Letters (A-Z)",
                                         font=(MAIN_FONT_NAME, 15, "bold"),
                                         command=self.update_caps
                                         )
        self.create_window(210, 366, window=self.caps_switch)
        self.caps_switch.select()
        self.pword_caps = True
        # digits
        self.digits_switch = ctk.CTkSwitch(self,
                                           switch_width=35,
                                           switch_height=16,
                                           corner_radius=10,
                                           text="Digits (0-9)",
                                           font=(MAIN_FONT_NAME, 15, "bold"),
                                           command=self.update_digits
                                           )
        self.create_window(176, 393, window=self.digits_switch)
        self.digits_switch.select()
        self.digits = True
        # symbols
        self.symbols_switch = ctk.CTkSwitch(self,
                                            switch_width=35,
                                            switch_height=16,
                                            corner_radius=10,
                                            text="Symbols (@!$%&*)",
                                            font=(MAIN_FONT_NAME, 15, "bold"),
                                            command=self.update_symbols
                                            )
        self.create_window(200, 420, window=self.symbols_switch)
        self.symbols_switch.select()
        self.symbols = True

        # Other
        self.other_label = ctk.CTkLabel(self, text="Other", font=(MAIN_FONT_NAME, 30))
        self.create_window(525, 25, window=self.other_label)
        # Website
        self.website_label = ctk.CTkLabel(self, text="Website", font=(MAIN_FONT_NAME, 14, "bold"))
        self.create_window(450, 65, window=self.website_label)
        self.website_entry = ctk.CTkEntry(self, placeholder_text="Website Address", font=(MAIN_FONT_NAME, 13))
        self.create_window(518, 95, window=self.website_entry, width=200, height=35)
        # Notes
        self.notes_label = ctk.CTkLabel(self, text="Notes", font=(MAIN_FONT_NAME, 14, "bold"))
        self.create_window(440, 150, window=self.notes_label)
        self.notes = ctk.CTkTextbox(self, font=(MAIN_FONT_NAME, 15))
        self.create_window(518, 265, window=self.notes)
        # save
        self.save_btn = ctk.CTkButton(self,
                                      text="Save",
                                      font=(MAIN_FONT_NAME, 15),
                                      corner_radius=7,
                                      command=self.save_login
                                      )
        self.create_window(515, 420, window=self.save_btn)

    def update_length(self, val: Any):
        self.pword_len_label.configure(text=str(int(val)))
        self.pword_length = str(int(val))

    def update_caps(self):
        self.pword_caps = not self.pword_caps

    def update_digits(self):
        self.digits = not self.digits

    def update_symbols(self):
        self.symbols = not self.symbols

    def change_btn_img(self) -> None:
        if self.pwd_btn_state == "show":
            self.pwd_btn_state = "hide"
            self.show_pwd_btn.configure(image=hide_pwd)
            self.pwd.configure(show="")
        else:
            self.pwd_btn_state = "show"
            self.show_pwd_btn.configure(image=show_pwd)
            self.pwd.configure(show="*")

    def generate_password(self) -> None:
        digits, caps, symbols, length = self.digits, self.pword_caps, self.symbols, int(self.pword_length)

        chars = string.ascii_lowercase

        if digits:
            chars += string.digits
        if caps:
            chars += string.ascii_uppercase
        if symbols:
            chars += string.punctuation
        pword = "".join([secrets.choice(chars) for _ in range(length)])
        self.pwd.delete(0, ctk.END)
        self.pwd.insert(0, pword)
        # add generated password to clipboard, ready to paste
        self.clipboard_clear()
        self.clipboard_append(pword)

    def save_login(self):
        title: str = self.title_entry.get()
        user: str = self.usr_name.get()
        password: str = self.pwd.get()
        website: str = self.website_entry.get()
        note: str = self.notes.get(index1="1.0", index2=ctk.END)

        pwd_as_bytes = password.encode('utf-8')
        string_bytes = title.encode('utf-8')
        hashed_bytes = hashlib.sha256(string_bytes).digest()
        key = hashed_bytes[:16]
        cipher = AES.new(key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(pwd_as_bytes)
        encrypted_pwd = (nonce, ciphertext, tag)

        if not title:
            self.title_label.configure(text="Title must not be empty!", text_color="red")
            return

        # encrypting password and saving it
        if title in LOGIN_ENTRY_OPTIONS:
            # update entry values
            df = pandas.read_csv(LOGINS_FILE)
            login_row = df.loc[df["title"] == title]
            row_number = login_row.index.values[0]

            df.at[row_number, "user"] = user
            df.at[row_number, "password"] = encrypted_pwd
            df.at[row_number, "website"] = website
            df.at[row_number, "note"] = note
            df.to_csv(LOGINS_FILE, index=False)
        else:
            new_login: dict = {
                "title": [title],
                "user": [user],
                "password": [encrypted_pwd],
                "website": [website],
                "note": [note],
            }

            new_login_df = pd.DataFrame(new_login)
            new_login_df.to_csv(LOGINS_FILE, mode="a", index=False, header=False)

        update_entry_list()

    def load_saved_data(self, title):
        try:
            login_row = self.login_data.loc[self.login_data["title"] == title]
            row_number = login_row.index.values[0]
            login_row_dict = login_row.to_dict()
            title_txt = login_row_dict["title"][row_number]
            usr_txt = login_row_dict["user"][row_number]
            pword_txt = login_row_dict["password"][row_number]

            # decrypting password
            if pword_txt:
                encrypted_pword_txt = ast.literal_eval(pword_txt)
                nonce = encrypted_pword_txt[0]
                ciphertext = encrypted_pword_txt[1]
                string_bytes = title.encode('utf-8')
                hashed_bytes = hashlib.sha256(string_bytes).digest()
                key = hashed_bytes[:16]
                cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
                plaintext = cipher.decrypt(ciphertext)
                pword_txt = plaintext

            website_txt = login_row_dict["website"][row_number]
            note_txt = login_row_dict["note"][row_number]

            self.title_entry.insert(ctk.INSERT, title_txt)
            self.usr_name.insert(ctk.INSERT, usr_txt)
            self.pwd.insert(ctk.INSERT, pword_txt)
            self.website_entry.insert(ctk.INSERT, website_txt)
            self.notes.insert(ctk.INSERT, note_txt)
        except Exception as e:
            print(f"Exception: {e}")


class PasswordsFrame(ctk.CTkFrame):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)


class BottomBar(ctk.CTkFrame):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.settings_button = ctk.CTkButton(self,
                                             text="Settings",
                                             image=settings_image,
                                             fg_color=BLUE,
                                             command=open_settings)
        self.settings_button.pack(side=ctk.LEFT)

        self.entry_index = ctk.CTkLabel(self, text=f"{len(LOGIN_ENTRY_OPTIONS)} entries")
        self.entry_index.pack(side=ctk.RIGHT, padx=10)


class Settings(ctk.CTkToplevel):
    def __init__(self, master=None):
        super().__init__(master=master)

        self.geometry("400x300")
        self.minsize(width=400, height=300)
        self.maxsize(width=400, height=300)
        self.title("Settings")

        self.options = SettingsFrame(self, corner_radius=8, fg_color=BLUE)
        self.options.pack(fill=ctk.BOTH, expand=True, padx=5, pady=5)


class SettingsFrame(ctk.CTkFrame):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.theme_frame = ctk.CTkFrame(self, border_color="black")
        self.theme_frame.pack(padx=5, pady=5, fill=ctk.BOTH)

        theme = ctk.StringVar()

        def set_theme(mode=theme) -> None:
            customtkinter.set_appearance_mode(mode.get())

        # dark theme radiobutton
        self.dark_theme = ctk.CTkRadioButton(self.theme_frame, text="Dark theme",
                                             font=("", 12),
                                             variable=theme,
                                             value="dark",
                                             command=set_theme)
        self.dark_theme.grid(column=0, row=0, padx=50, pady=15)
        # light theme radiobutton
        self.light_theme = ctk.CTkRadioButton(self.theme_frame,
                                              text="Light theme",
                                              font=(MAIN_FONT_NAME, 12),
                                              variable=theme,
                                              value="light",
                                              command=set_theme,
                                              )
        self.light_theme.grid(column=1, row=0, padx=30, pady=15)

        current_mode = customtkinter.get_appearance_mode().lower()

        if current_mode == "dark":
            self.dark_theme.select()
        else:
            self.light_theme.select()


class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        # lock window size
        self.geometry("700x600")
        self.minsize(width=700, height=600)
        self.maxsize(width=700, height=600)
        self.title("Password Manager")

        self.folders_frame = FoldersFrame(self, border_color="white", corner_radius=0)
        self.folders_frame.pack(fill=ctk.X)

        self.passwords_frame = PasswordsFrame(self, corner_radius=0, fg_color=GREEN)
        self.passwords_frame.pack(fill=ctk.BOTH, expand=True)

        self.settings = BottomBar(self, corner_radius=0)
        self.settings.pack(fill=ctk.X, side=ctk.BOTTOM)

        self.current_pwd_page = PasswordPage(self.passwords_frame,
                                             bg=BLUE,
                                             highlightthickness=0)

        self.current_pwd_page.pack(fill=ctk.BOTH, expand=True, padx=3, pady=3, ipadx=100, ipady=100)

    def load_password(self, title):
        self.current_pwd_page.destroy()
        self.current_pwd_page = PasswordPage(self.passwords_frame,
                                             bg=BLUE,
                                             highlightthickness=0)
        self.current_pwd_page.load_saved_data(title)
        self.current_pwd_page.pack(fill=ctk.BOTH, expand=True, padx=3, pady=3, ipadx=100, ipady=100)


if __name__ == "__main__":
    app = App()
    app.mainloop()
