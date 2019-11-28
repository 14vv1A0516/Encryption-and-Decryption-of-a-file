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

def decrypt():

 print("In encrypt method file is '{0}'".format(ifile))
 print("In encrypt method cert is '{0}'".format(icert))

 # extract pri key to decrypt AES key
 p12 = crypto.load_pkcs12(file(icert,"rb").read(),"user1")
 pri_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, p12.get_privatekey())
 with open("enc_key_file.txt","rb") as ekf:
  ef = ekf.read()
  ekf.close()
 print("\nenc_key_stream is \n")
 print(ef)
 
 rsa_pri_key = RSA.importKey(pri_key)
 rsa_pri_key = PKCS1_OAEP.new(rsa_pri_key)
 dec_key = rsa_pri_key.decrypt(ef)
 print("\nAES key is \n")
 print(dec_key) # Dec key
 # AES key extracted
 
 chunksize = 64*1024
 
 sp = ifile.split("/")
 ln = len(sp)
 print("len is '{0}'".format(ln))
 print(sp[ln-1])
 print(sp)
 outputFile = "final_"+ sp[ln-1]
 
 # File decryption starts
 with open(ifile, 'rb') as infile:
  filesize = long(infile.read(16))
  IV = infile.read(16)
  decryptor = AES.new(dec_key, AES.MODE_CBC, IV)
  
  with open(outputFile, 'wb') as outfile:
   while True:
    chunk = infile.read(chunksize)
    if len(chunk) == 0:
     break
    outfile.write(decryptor.decrypt(chunk))
   outfile.truncate(filesize)
 # File decrypted


root  = Tk()
root.title("File Decryption")
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
#T1.insert(tk.END, ifile)

T2 = Entry(root, width=30)
T2.place(x=130,y=70)
#T2.insert(tk.END, icert)

b1 = Button(root, text="SELECT FILE",fg="Red",font="Times", command=select_file)
b1.place(x=420,y=23)

b1 = Button(root, text="SELECT KEY",fg="Red",font="Times", command=select_cert)
b1.place(x=420,y=63)

b2 = Button(root, text="Decrypt",fg="green",font="Verdana 15 bold", command= decrypt)
b2.place(x=100,y=100)

b3 = Button(root, text="Reset",fg="green",font="Verdana 15 bold", command= "")
b3.place(x=220,y=100)

b4 = Button(root, text="Close",fg="green",font="Helvetica 15 bold", command=close_root_window)
b4.place(x=320,y=100)

root.mainloop()

