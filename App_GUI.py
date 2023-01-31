import base64
from tkinter import *
from tkinter import filedialog
from tkinter import messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


window = Tk()
window.title('Encrypt1.0')
window.geometry('550x300')
window.resizable(False, False)
window.iconbitmap()
window.configure(bg='#595c5a')


Canvas1 = Canvas(window, bg="white", height=275, width=320)
Canvas1.place(x=10, y=10)

Canvas2 = Canvas(window, bg="white", height=275, width=185, relief = RAISED)
Canvas2.place(x=350, y=10)

l0 = Label(window, text='File Encryptor', font=('Times', 22), bg="white")
l0.place(x=360, y=120)

l2 = Label(window, text='Message: ')
l2.place(x=25, y=250)


def browseFiles():
    global f1
    f1 = filedialog.askopenfilename(initialdir=r"C:\Users\nitya\PycharmProjects\Encrypt", title="Select a File",
                                    filetypes=(("Text files", "*.txt*"), ("all files", "*.*")))
    l2.configure(text="File Opened: " + f1)


b1 = Button(window, text="Browse Files", command=browseFiles, activebackground='#709191', font=('Helvetica', 12))
b1.place(x=140, y=35)

pw = Entry(window, width=23, borderwidth=3, show='*', font=('Helvetica', 12))
pw.place(x=25, y=75)


def pass_submit():
    global my_key
    p = pw.get()
    password = p.encode()
    my_salt = b'\xfb\x8af\xd4\xdf\x05D\xa2\xbf^\xbd\xd5-\xaac\x8c'
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256, length=32, salt=my_salt, iterations=100000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password))
    my_key = key.decode()
    pw.delete(0, END)


b2 = Button(window, text='OK', command=pass_submit, width=5, font=('Helvetica', 12))
b2.place(x=250, y=73)


def show_password():
    if pw.cget('show') == '*':
        pw.config(show='')
    else:
        pw.config(show='*')


check_box = Checkbutton(window, text='Show Password', command=show_password)
check_box.place(x=25, y=105)


def Encrypt():
    filename = f1
    f = open(filename, 'rb')
    e_file = f.read()
    m = Fernet(my_key)
    e_data = m.encrypt(e_file)
    f = open(filename, 'wb')
    f.write(e_data)
    f.close()
    messagebox.showinfo('Message', 'Successfully Encrypted')


b3 = Button(window, text="Encrypt", command=Encrypt, font=('Helvetica', 12))
b3.place(x=25, y=165)


def Decrypt():
    filename = f1
    f = open(filename, 'rb')
    e_file = f.read()
    m = Fernet(my_key)
    try:
        e_data = m.decrypt(e_file)
        f = open(filename, 'wb')
        f.write(e_data)
        f.close()
        messagebox.showinfo('Message', 'Successfully Decrypted')
    except:
        messagebox.showinfo('Message', 'Incorrect Password')


b4 = Button(window, text="Decrypt", command=Decrypt, font=('Helvetica', 12))
b4.place(x=240, y=165)

window.mainloop()