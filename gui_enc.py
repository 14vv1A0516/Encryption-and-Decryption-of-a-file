 
from tkinter import *
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
import os, random
from Crypto.Cipher import AES
from Crypto.Hash import  SHA256
from OpenSSL import crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
import zlib
import base64

global icert
global ifile

ifile=""
icert=""

def select_file():
 global ifile,T1
 ifile = filedialog.askopenfilename()
 print("file is '{0}'".format(ifile))
 T1.insert(tk.END, ifile)
 messagebox.showinfo("File selected", "File selected is '{0}' ".format(ifile))

def select_cert():
 global icert,T2
 icert = filedialog.askopenfilename()
 T2.insert(tk.END, icert)
 messagebox.showinfo("File selected", "File selected is '{0}' ".format(icert))

def getKey(password):
 hasher = SHA256.new(password) 
 return hasher.digest()

def encrypt():

 print("In encrypt method file is '{0}'".format(ifile))
 print("In encrypt method cert is '{0}'".format(icert))

 filename = ifile
 password = os.urandom(32)
 
 # store plain AES key(SHA_256 hash of randomly generated 256 bit no) in key_file 

 with open("key_file.txt","w") as kf:
  password = str(password)
  kf.write(password)
  kf.close()

 key = getKey(password)

 chunksize = 64*1024
 sp = ifile.split("/")
 ln = len(sp)
 print("len is '{0}'".format(ln))
 print(sp[ln-1])
 print(sp)
 outputFile = "enc_"+ sp[ln-1]
 filesize = str(os.path.getsize(filename)).zfill(16)
 IV = ''
 
 for i in range(16):
  
  IV += chr(random.randint(0, 0xFF))
 encryptor = AES.new(key, AES.MODE_CBC, IV)
 
 with open(filename, 'rb') as infile:
  with open(outputFile, 'wb') as outfile:
   outfile.write(filesize)
   outfile.write(IV)
   while True:
    chunk = infile.read(chunksize)
    if len(chunk) == 0:
     break
    elif len(chunk) % 16 != 0:
     chunk += ' ' * (16 - (len(chunk) % 16))
    outfile.write(encryptor.encrypt(chunk))

 # Key text encryption using RSA pub key and store in text file
 cert = crypto.load_certificate(crypto.FILETYPE_ASN1, open(icert,"rb").read())
 print(crypto.dump_publickey(crypto.FILETYPE_PEM,cert.get_pubkey()))
 pk = crypto.dump_publickey(crypto.FILETYPE_PEM,cert.get_pubkey())
 
 # RSA 2048 bit public key extracted from .der 
 pub_key = RSA.importKey(pk)
 pub_key = PKCS1_OAEP.new(pub_key)
 enc_text = pub_key.encrypt(key)
 print("enc text of key stream is\n")
 print(enc_text)

 # enc key in enc_key_file

 with open("enc_key_file.txt","w") as ekf:
  ekf.write(enc_text)
  ekf.close()

def reset():
  global ifile,T
  #var = T.get('1.0',tk.END).replace(ifile,' ')
  #T.replace('1.0',tk.END,var) 

root  = Tk()
root.title("File Encryption")
def close_root_window():
  root.destroy()
root.geometry("550x600")

ll = tk.Label(root, text='Input file')
ll.place(x=20,y=30)
l2 = tk.Label(root, text='Input certificate')
l2.place(x=20,y=70)
#global T

#T = tk.Text(root, height=2, width=30)
#T.pack()
#T.insert(tk.END, ifile)

T1 = Entry(root, width=30)
T1.place(x=130,y=30)  
T1.insert(tk.END, ifile)

T2 = Entry(root, width=30)
T2.place(x=130,y=70)  
T2.insert(tk.END, icert)

b1 = Button(root, text="SELECT FILE",fg="Red",font="Times", command=select_file)
b1.place(x=420,y=23)

b1 = Button(root, text="SELECT KEY",fg="Red",font="Times", command=select_cert)
b1.place(x=420,y=63)

b2 = Button(root, text="Encrypt",fg="green",font="Verdana 15 bold", command= encrypt)
b2.place(x=100,y=100)

b3 = Button(root, text="Reset",fg="green",font="Verdana 15 bold", command= reset)
b3.place(x=220,y=100)

b4 = Button(root, text="Close",fg="green",font="Helvetica 15 bold", command=close_root_window)
b4.place(x=320,y=100)

root.mainloop()

