"""
#### 2-Clause BSD licence:

Copyright 2023 Alfredo Ortega @ortegaalfredo

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""
import socket
import select
import time
import json
import http.client
import ssl
import sys

# Client class
class Neuroengine:
    #__init__(): Initializes a new instance of the neuroengine class.
    #Parameters:
    #   server_address: A string representing the server address.
    #   server_port: An integer representing the server port.
    #   service_name: A string representing the name of the service.
    #   key (optional): A string representing an optional key (not required).
    #   verify_ssl (optional): A boolean indicating whether to verify SSL certificates or not.

    def __init__(self, service_name, server_address="api.neuroengine.ai",server_port=443,key="",verify_ssl=True):
        self.server_address=server_address
        self.server_port=server_port
        self.service_name=service_name
        self.key=key
        self.verify_ssl=verify_ssl

    #getmodel(): Return a list of active LLM models in the server

    def getModels(self):
        command = {'command': 'getmodels' }
        response=self.send(command)
        return response

    def request(self, prompt,temperature=1.0,top_p=0.9,min_p=0.0,top_k=40,repetition_penalty=1.2,max_new_len=128,seed=0,raw=False,tries=5,gettokens=20,streamkey=""):
        """ request(): Sends a request to the server and returns the response.
        Parameters:
        - prompt (str): The text prompt that will be used to generate the response.
        - temperature (float): Controls the randomness of the output. Higher values (e.g., 1.0) make the output more random, while lower values (e.g., 0.2) make it more deterministic. Default is 1.0.
        - top_p (float): Determines the cumulative probability threshold for generating the output. Tokens with cumulative probability higher than this value are considered for sampling. Default is 0.9.
        - top_k (int): Controls the number of top tokens to consider for generating the output. Only the top-k tokens are used for sampling. Default is 40.
        - min_p (float): Activates min_p sampler, works if 0.0<min_p<1.0
        - repetition_penalty (float): Controls the penalty applied to repeated tokens in the output. Higher values (e.g., 1.2) discourage repeating tokens, while lower values (e.g., 0.8) encourage repetition. Default is 1.2.
        - max_new_len (int): Controls the maximum length of the generated response. The response will be truncated if its length exceeds this value. Default is 128.
        - seed (int): The random seed for generating the response. Use this to control the reproducibility of the output. Default is 0.
        - raw (bool): If True, the response will be returned as raw JSON string; if False, the reply content will be extracted from the JSON. Default is False.
        - tries (int): The number of attempts to send the request in case of errors before giving up. Default is 5.
        - gettokens (int): The amont of tokens to get in each streaming call, default is 20. This is a partial response, you must call several times using the same streamkey until the function return an empty string.
        - streamkey (str): An unique ID to identify your stream session. Generate this ID securely, at least 32 bytes. If no streamkey is provided, the request will be not streamed, and the complete reply will be returned in a single call.
    Returns:
        - str: The generated response or an error message, depending on the success of the request. """

        if (prompt is None):
            return("")
        # Create a JSON message
        command = {
            'message': prompt,
            'temperature': temperature,
            'top_p':top_p,
            'top_k':top_k,
            'min_p':min_p,
            'repetition_penalty':repetition_penalty,
            'max_new_len':max_new_len,
            'seed':seed,
            'raw' :str(raw),
            'key' : streamkey,
            'gettokens': gettokens
        }
        try:
            count=0
            while(count<tries):
                count+=1
                response=self.send(command)
                if int(response["errorcode"])==0:
                        break
        except KeyboardInterrupt: sys.exit(0)
        except Exception as e:
            response={}
            response["reply"]=f"Connection error. Try in a few seconds ({str(e)})"
        return response["reply"]

    def send(self,command):
        json_data = json.dumps(command)
        # Create an HTTP connection
        socket.setdefaulttimeout(180)
        if (self.verify_ssl):
            connection = http.client.HTTPSConnection(self.server_address, self.server_port)
        else:
            connection = http.client.HTTPSConnection(self.server_address, self.server_port, context = ssl._create_unverified_context())

        # Send a POST request with the JSON message
        headers = {'Content-Type': 'application/json'}
        connection.request('POST', f'/{self.service_name}', json_data, headers)

        # Get the response from the server
        response = connection.getresponse()
        response = response.read().decode()

        connection.close()
        response = json.loads(response)
        return response

# Server class, use it to share your LLM

class NeuroengineServer:

    def __init__(self, server_address="api.neuroengine.ai",server_port=4444):
        """__init__(): Initializes a new instance of the neuroengine Server class
            Parameters:
               server_address: A string representing the server address.
               server_port: An integer representing the server port.
               service_name: A string representing the name of the service."""
        self.server_address=server_address
        self.server_port=server_port

    def login(self,service_name,service_key):
        socket.setdefaulttimeout(180)
        # Create a socket object
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Wrap the socket with SSL
        ssl_context = ssl.create_default_context()
        self.ssl_socket = ssl_context.wrap_socket(self.client_socket,server_hostname=self.server_address)
        # Connect to the server
        self.ssl_socket.connect((self.server_address,self.server_port))
        # Login to server
        logindata={}
        logindata["user"]=service_name
        logindata["key"]=service_key
        data=json.dumps(logindata)
        self.ssl_socket.sendall(data.encode())
        response = self.ssl_socket.recv(20480)
        if (response.strip().decode()=="OK"):
            self.service_name=service_name
            self.service_key=service_key
            self.pingtime=time.time()
            return(0)
        else:
            self.ssl_socket.shutdown(socket.SHUT_WR)
            return(-1)

    def is_socket_closed(self,sock):
        if time.time()-self.pingtime>120:
            return True
        else: 
            return False

    def has_bytes_to_receive(self,sock):
        try:
            r, _, _ = select.select([sock], [], [], 0)
            return sock in r
        except socket.error:
            return False


    def listen(self,answerCallback):
            # Listen for data from the server
        while True:
            # Attempt reconnect if server is down
            while(self.is_socket_closed(self.client_socket)):
                print("Neuroengine.ai: connection error, retrying...")
                time.sleep(5)
                try:
                    self.login(self.service_name,self.service_key)
                except: pass
            try:
                # Check if there are bytes in the socket
                if self.has_bytes_to_receive(self.ssl_socket)==False:
                    time.sleep(0.1)
                    continue
                # Read bytes
                data=b""
                chunklen=4096
                while True:
                    chunk = self.ssl_socket.recv(chunklen)
                    data+=chunk
                    if len(chunk)<chunklen: break
                    if len(data)>(8192*6): break
                if not data:
                    self.pingtime=0
                    continue
                received_string = data.decode()
                request = json.loads(received_string)
                # We received a keep-alive ping
                if ("ping" in request):
                    self.pingtime=time.time()
                    continue
                # Process request
                response=answerCallback(request).encode()
                # Send len
                self.ssl_socket.sendall(("%08X" % len(response)).encode())
                # Send message
                self.ssl_socket.sendall(response)
            except Exception as e:
                print(f"Error: {str(e)}")
                self.pingtime=0
                pass

if __name__ == "__main__":
    # Define the server address and port
    if len(sys.argv)<2:
        print(f"Usage: {sys.argv[0]} <prompt>")
        exit(-1)
    service_name = 'Neuroengine-Large'
    api=Neuroengine(service_name=service_name)
    prompt=sys.argv[1]
    response=api.request(prompt)
    print(response)
