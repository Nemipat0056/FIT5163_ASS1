from crypto_handler import CryptoHandler
from email_handler import EmailHandler

class SecureEmailApp:
    def __init__(self, email, password, smtp_server, smtp_port, imap_server, imap_port, crypto_password):
        self.email_handler = EmailHandler(email, password, smtp_server, smtp_port, imap_server, imap_port)
        self.crypto = CryptoHandler(crypto_password)
        self._trust_list = set()

    def send_secure_email(self, to_email, subject, body):
        encrypted_body = self.crypto.encrypt_message(body)
        signature = None
        public_key = None
        if to_email not in self._trust_list:
            signature = self.crypto.sign_message(body.encode())
            public_key = self.crypto.get_public_key()
        return self.email_handler.send_email(to_email, subject, encrypted_body, signature, public_key)

    def receive_emails(self):
        for email in self.email_handler.receive_emails():
            if email['is_secure']:
                try:
                    decrypted_body = self.crypto.decrypt_message(email['encrypted_body'])
                    email['body'] = decrypted_body
                    email['decrypted'] = True
                    if email['signature'] and email['public_key']:
                        public_key = self.crypto.load_public_key(email['public_key'].encode())
                        if self.crypto.verify_signature(decrypted_body.encode(), email['signature'], public_key):
                            self._trust_list.add(email['sender'])
                            email['verified'] = True
                        else:
                            email['verified'] = False
                    else:
                        email['verified'] = email['sender'] in self._trust_list
                except Exception as e:
                    print(f"Error decrypting secure email: {e}")
                    email['decrypted'] = False
                    email['verified'] = False
            else:
                email['decrypted'] = True
                email['verified'] = False
            yield email

    @property
    def trust_list(self):
        return list(self._trust_list)