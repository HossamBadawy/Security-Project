import socket, io
import time
import select
import queue
import sys,os
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import PIL.Image as Image
from PIL import ImageFile
ImageFile.LOAD_TRUNCATED_IMAGES = True
from gui import *
import psycopg2
import base64
import rsa

from stegano import lsb


ENCODING = 'utf-8'
HOST = 'localhost'
PORT = 8889

class Client(threading.Thread):


    
    def __init__(self, host, port):
        super().__init__(daemon=True, target=self.run)

        self.host = host
        self.port = port
        self.sock = None
        self.connected = self.connect_to_server()
        self.buffer_size = 1024

        self.queue = queue.Queue()
        self.lock = threading.RLock()

        self.login = ''
        self.target = ''
        self.login_list = []

        if self.connected:
            self.gui = GUI(self)
            self.start()
            self.gui.start()
            # Only gui is non-daemon thread, therefore after closing gui app will quit

    
    def connect_to_server(self):
        """Connect to server via socket interface, return (is_connected)"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((str(self.host), int(self.port)))
        except ConnectionRefusedError:
            print("Server is inactive, unable to connect")
            return False
        return True

    def run(self):
        """Handle client-server communication using select module"""
        inputs = [self.sock]
        outputs = [self.sock]
        while inputs:
            try:
                read, write, exceptional = select.select(inputs, outputs, inputs)
            # if server unexpectedly quits, this will raise ValueError exception (file descriptor < 0)
            except ValueError:
                print('Server error')
                GUI.display_alert('Server error has occurred. Exit app')
                self.sock.close()
                break

            if self.sock in read:
                with self.lock:
                    try:
                        data = "".encode(ENCODING)
                        dataString = data.decode(ENCODING)
                        while(not "EOF" in dataString):
                          data += self.sock.recv(3965758)
                          dataString = data.decode(ENCODING)  
                        #   print('lsa')
                        # print("wesel")
                    except socket.error:
                        print("Socket error")
                        GUI.display_alert('Socket error has occurred. Exit app')
                        self.sock.close()
                        break

                self.process_received_data(data)

            if self.sock in write:
                if not self.queue.empty():
                    data = self.queue.get()
                    self.send_message(data)
                    self.queue.task_done()
                else:
                    time.sleep(0.05)

            if self.sock in exceptional:
                print('Server error')
                GUI.display_alert('Server error has occurred. Exit app')
                self.sock.close()
                break

    def process_received_data(self, data):
        """Process received message from server"""
        if data:
            message = data.decode(ENCODING)
            message = message.split('\n')

            for msg in message:
                if msg != '':
                    msg = msg.split(';')

                    if msg[0] == 'msg':
                        try:
                            image_data = base64.b64decode(msg[3])
                        except:
                            try:
                                image_data = base64.b64decode(msg[3]+"=")
                            except:
                                try:
                                    image_data = base64.b64decode(msg[3]+"==")
                                except:
                                    image_data = base64.b64decode(msg[3]+"===")
                        
                        image = open("test1.png","wb")
                        image.write(bytearray(image_data))
                       
                        clear_message = lsb.reveal("test1.png")
                        #######DECRYPTION GOES HERE##########
                        if(msg[2]!='all'):
                            toDecrypt = msg[3].split('MOSALAH')

                            clear_message, verify = self.decrypt_message(clear_message, toDecrypt[1], msg[1], msg[2])
                        
                         #####################################
                        text = msg[1] + ' >> ' + clear_message + '\n'
                        # print( "recieved")
                        self.gui.display_message(text)

                        # if chosen login is already in use
                        if msg[2] != self.login and msg[2] != 'ALL':
                            self.login = msg[2]

                    elif msg[0] == 'login':
                        self.gui.display_alert("Success")
                        self.gui.login_window.root.quit()
                        time.sleep(1)
                        self.gui.main_window.update_login_list(msg[1:])
                    elif msg[0] == 'registerC':
                        self.gui.display_alert("Success")
                        
                        self.gui.login_window.root.quit()
                        time.sleep(1)
                        self.gui.main_window.update_login_list(msg[1:])
                    elif msg[0] == 'registerF':
                        self.gui.display_alert("Failed to Regitser")

                    elif msg[0] == 'loginFail':
                        self.gui.display_alert("Failed to login")

    def notify_server(self, action, action_type):
        """Notify server if action is performed by client"""
        self.queue.put(action)
        if action_type == "login":
            self.login = action.decode(ENCODING).split(';')[1]
        elif action_type == "logout":
            self.sock.close()

    def decrypt_message(self, message, signature, usernameS, usernameR):
        connection = None
        flag = True
        
        try:
            connection = psycopg2.connect(user = "postgres",
                                        password = "123456",
                                        host = "127.0.0.1",
                                        port = "5432",
                                        database = "security")
            cursor1 = connection.cursor()
            cursor2 = connection.cursor()
            cursor1.execute('SELECT publickey from public."Keys" where username = %s', (usernameS,))
            cursor2.execute('SELECT privatekey from public."Keys" where username = %s', (usernameR,))
            

            record1 = cursor1.fetchall()
            publicKeyOfSender = record1[0][0]

            record2 = cursor1.fetchall()
            privateKeyOfReciever = record2[0][0]
            
        except (Exception, psycopg2.Error) as error :
            print ("Error while connecting to PostgreSQL", error)
            flag = False
        finally:
            #closing database connection.
                if(connection):
                    connection.commit()
                    cursor1.close()
                    cursor2.close()
                    connection.close()
                    print("PostgreSQL connection is closed")
        

        verify = rsa.verify(message, signature, publicKeyOfSender)
        crypto = rsa.decrypt(message, privateKeyOfReciever)
        

        return crypto, verify

    def encrypt_message(self, message, usernameS, usernameR):
        connection = None
        flag = True
        
        try:
            connection = psycopg2.connect(user = "postgres",
                                        password = "123456",
                                        host = "127.0.0.1",
                                        port = "5432",
                                        database = "security")
            cursor1 = connection.cursor()
            cursor2 = connection.cursor()
            cursor1.execute('SELECT publickey from public."Keys" where username = %s', (usernameR,))
            cursor2.execute('SELECT privatekey from public."Keys" where username = %s', (usernameS,))
            

            record1 = cursor1.fetchall()
            publicKeyOfReciever = record1[0][0]

            record2 = cursor1.fetchall()
            privateKeyOfSender = record2[0][0]
            
        except (Exception, psycopg2.Error) as error :
            print ("Error while connecting to PostgreSQL", error)
            flag = False
        finally:
            #closing database connection.
                if(connection):
                    connection.commit()
                    cursor1.close()
                    cursor2.close()
                    connection.close()
                    print("PostgreSQL connection is closed")
        

        message = message.encode(ENCODING)
        crypto = rsa.encrypt(message, publicKeyOfReciever)
        signature = rsa.sign(crypto, privateKeyOfSender, 'SHA-1')

        return crypto, signature
        

    def send_message(self, data):
        """"Send encoded message to server"""
        
        with self.lock:
            try:
                splitted_data=(str(data.decode(ENCODING))).split(";")
                print(splitted_data)
                # print(splitted_data, "splittedarray")
                if(splitted_data[0] == "msg"):
                    msg=splitted_data[3]
                    #### ENCRYPTION #####
                    if(msg[2]!='all'):
                        crypto, signature = self.encrypt_message(msg,splitted_data[1],splitted_data[2])
                        crypto = crypto.decode(ENCODING)
                        signature = signature.decode(ENCODING)
                        msg =  crypto + 'MOSALAH' + signature
                       
                    #####################
                    msg = msg.encode(ENCODING)   
                    secret_msg = lsb.hide("test.png", msg)
                    secret_msg.save("testEncrypted.png")
                    with open("testEncrypted.png", "rb") as image_file:
                        encoded_string = (base64.b64encode(image_file.read())).decode(ENCODING)
                    
                    
                    
                    
                   # print(imgByteArr)
                    splitted_data=(str(data.decode(ENCODING))).split(";")
                    string_data = splitted_data[0:3]
                    string_data.append((encoded_string))
                    string_data.append("EOF")
                    data = (";".join(string_data)).encode(ENCODING)
                    # print(sys.getsizeof(data))
                elif(splitted_data[0] == "file"):
                    print()
                else:
                    string_data = ((str(data.decode(ENCODING))).split(";"))
                    string_data.append("EOF")
                    data = (";".join(string_data)).encode(ENCODING)
                    # print(data)
                self.sock.send(data)
            except socket.error:
                self.sock.close()
                GUI.display_alert('Server error has occurred. Exit app')


# Create new client with (IP, port)
if __name__ == '__main__':
    Client(HOST, PORT)
