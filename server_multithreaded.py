import socket
import threading
import queue
import time
import hashlib, binascii, os
import psycopg2
import stegano
import cv2
from LSBSteg import LSBSteg

ENCODING = 'utf-8'
HOST = 'localhost'
PORT = 8889


class Server(threading.Thread):
    def __init__(self, host, port):
        super().__init__(daemon=False, target=self.run)

        self.host = host
        self.port = port
        self.buffer_size = 100000
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.connection_list = []
        self.login_list = {}
        self.queue = queue.Queue()

        self.shutdown = False
        try:
            self.sock.bind((str(self.host), int(self.port)))
            self.sock.listen(10)
            self.sock.setblocking(False)
        except socket.error:
            self.shutdown = True

        if not self.shutdown:
            listener = threading.Thread(target=self.listen, daemon=True)
            receiver = threading.Thread(target=self.receive, daemon=True)
            sender = threading.Thread(target=self.send, daemon=True)
            self.lock = threading.RLock()

            listener.start()
            receiver.start()
            sender.start()
            self.start()

    def run(self):
        """Main thread method"""
        print("Enter \'quit\' to exit")
        while not self.shutdown:
            message = input()
            if message == "quit":
                self.sock.close()
                self.shutdown = True

    def listen(self):
        """Listen for new connections"""
        print('Initiated listener thread')
        while True:
            try:
                self.lock.acquire()
                connection, address = self.sock.accept()
                connection.setblocking(False)
                if connection not in self.connection_list:
                    self.connection_list.append(connection)
            except socket.error:
                pass
            finally:
                self.lock.release()
            time.sleep(0.050)

    def receive(self):
        """Listen for new messages"""
        print('Initiated receiver thread')
        while True:
            if len(self.connection_list) > 0:
                for connection in self.connection_list:
                    try:
                        self.lock.acquire()
                        data = "".encode(ENCODING)
                        dataString = data.decode(ENCODING)
                        while(not "EOF" in dataString):
                          data += connection.recv(3965758)
                          dataString = data.decode(ENCODING)                          
                        
                        # print(data)
                    except socket.error:
                        data = None
                    finally:
                        self.lock.release()

                    self.process_data(data, connection)

    def send(self):
        """Send messages from server's queue"""
        print('Initiated sender thread')
        while True:
            if not self.queue.empty():
                target, origin, data = self.queue.get()
                dataString = (str(data.decode(ENCODING))).split(';')
                dataString.append('EOF')
                data = (';'.join(dataString)).encode(ENCODING)
                
                if target == 'all':
                    self.send_to_all(origin, data)
                else:
                    self.send_to_one(target, data)
                self.queue.task_done()
            else:
                time.sleep(0.05)

    def send_to_all(self, origin, data):
        """Send data to all users except origin"""
        if origin != 'server':
            origin_address = self.login_list[origin]
        else:
            origin_address = None

        for connection in self.connection_list:
            if connection != origin_address:
                try:
                    self.lock.acquire()
                    print(data)
                    connection.send(data)
                except socket.error:
                    self.remove_connection(connection)
                finally:
                    self.lock.release()

    def send_to_one(self, target, data):
        """Send data to specified target"""
        target_address = self.login_list[target]
        try:
            self.lock.acquire()
            target_address.send(data)
        except socket.error:
            self.remove_connection(target_address)
        finally:
            self.lock.release()
    
    def registerDB(self, user, hashed, salt):
        connection = None
        flag = True
        try:
            connection = psycopg2.connect(user = "postgres",
                                        password = "123456",
                                        host = "localhost",
                                        port = "5432",
                                        database = "security")
            cursor = connection.cursor()
            # cursor.execute("Insert into public.users values('"+user+"','"+hashed+"','"+salt+"');")
            cursor.execute('INSERT INTO public.users (username, hash, salt) VALUES (%s, %s, %s)', (user, hashed, salt))
        except (Exception, psycopg2.Error) as error :
            print ("Error while connecting to PostgreSQL", error)
            flag = False
        finally:
            #closing database connection.
                if(connection):
                    connection.commit()
                    cursor.close()
                    connection.close()
                    print("PostgreSQL connection is closed")        
                return flag

    def process_data(self, data, connection):
        """Process received data"""
        #print("processing")#
        if data:
            message = data.decode(ENCODING)
            message = message.split(";", 3)
            if message[0] == 'register':
                tmp_login = message[1]
                tmp_login2 = message[2]
                salt, hashed = self.hash_password(tmp_login2)
                flag = self.registerDB(tmp_login, hashed.decode('ascii'), salt.decode('ascii'))
                if flag:
                    print(message[1] + ' has registered')
                    self.login_list[message[1]] = connection
                    logins = 'registerC'
                    for login in self.login_list:
                        logins += ';' + login
                    logins += ';' + message[1]
                    logins += ';all' + '\n'
                    self.queue.put((message[1], 'server', logins.encode(ENCODING)))
                    # print(message[1] + ' has logged in')
                    # self.update_login_list()
                else:
                    print(message[1] + 'failed registered')
                    self.login_list[message[1]] = connection
                    logins = 'registerF'
                    for login in self.login_list:
                        logins += ';' + login
                    logins += ';' + message[1]+'\n'
                    self.queue.put((message[1], 'server', logins.encode(ENCODING)))
                    # self.update_login_list()              
            elif message[0] == 'login':
                tmp_login = message[1]
                tmp_login2 = message[2]
                
                flag = self.loginDB(tmp_login, tmp_login2)

                if flag:
                    self.login_list[message[1]] = connection
                    print(message[1] + ' has logged in')
                    self.update_login_list()
                else:
                    print("Invalid Username or password")
                    self.login_list[message[1]] = connection
                    logins = 'loginFail'
                    for login in self.login_list:
                        logins += ';' + login
                    logins += ';' + message[1]+'\n'
                    self.queue.put((message[1], 'server', logins.encode(ENCODING)))

            elif message[0] == 'logout':
                self.connection_list.remove(self.login_list[message[1]])
                if message[1] in self.login_list:
                    del self.login_list[message[1]]
                print(message[1] + ' has logged out')
                self.update_login_list()
           
            elif (message[0] == 'msg') and message[2] != 'all':
                msg = data.decode(ENCODING) + '\n'    
                data = msg.encode(ENCODING)
                
                self.queue.put((message[2], message[1], data))

            elif message[0] == 'msg':
                msg = data.decode(ENCODING) + '\n'
                data = msg.encode(ENCODING)
                self.queue.put(('all', message[1], data))

    def remove_connection(self, connection):
        """Remove connection from server's connection list"""
        self.connection_list.remove(connection)
        for login, address in self.login_list.items():
            if address == connection:
                del self.login_list[login]
                break
        self.update_login_list()

    def update_login_list(self):
        """Update list of active users"""
        logins = 'login'
        for login in self.login_list:
            logins += ';' + login
        logins += ';all' + '\n'
        self.queue.put(('all', 'server', logins.encode(ENCODING)))

    def hash_password(self,password):
    
        salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
        pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), 
                                    salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        return salt, pwdhash 
    # (salt + pwdhash).decode('ascii')

    def verify_password(self,stored_password, provided_password, salt):
        """Verify a stored password against one provided by user"""
        # (salt + pwdhash).decode('ascii')
        stored_password = stored_password.decode('ascii')
        salt = salt.decode('ascii')

        pwdhash = hashlib.pbkdf2_hmac('sha512', 
                                    provided_password.encode('utf-8'), 
                                    salt.encode('ascii'), 
                                    100000)
        pwdhash = binascii.hexlify(pwdhash).decode('ascii')
        print(pwdhash)
        return pwdhash == stored_password

    def loginDB(self, user, hashed):
        connection = None
        flag = True
        try:
            connection = psycopg2.connect(user = "postgres",
                                        password = "123456",
                                        host = "127.0.0.1",
                                        port = "5432",
                                        database = "security")
            cursor = connection.cursor()
            cursor.execute('SELECT * from public.users where username = %s', (user,))
            
            record = cursor.fetchall()
            print(record)
            if len(record) == 0:
                flag = False
            else:
                flag = self.verify_password(record[0][1].encode('ascii'),hashed,record[0][2].encode('ascii'))
        except (Exception, psycopg2.Error) as error :
            print ("Error while connecting to PostgreSQL", error)
            flag = False
        finally:
            #closing database connection.
                if(connection):
                    connection.commit()
                    cursor.close()
                    connection.close()
                    print("PostgreSQL connection is closed")
                return flag
# Create new server with (IP, port)
if __name__ == '__main__':
    server = Server(HOST, PORT)
