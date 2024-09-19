from secure_email_app import SecureEmailApp
import getpass

def main():
    print("Welcome to the Secure Email Application!")
    email = input("Enter your email address: ")
    password = getpass.getpass("Enter your email password: ")
    crypto_password = getpass.getpass("Enter a password for encryption: ")
    
    app = SecureEmailApp(email, password, 'smtp.gmail.com', 587, 'imap.gmail.com', 993, crypto_password)
    
    while True:
        print("\n1. Send secure email")
        print("2. Check emails")
        print("3. View trust list")
        print("4. Exit")
        choice = input("Enter your choice (1-4): ")
        
        if choice == '1':
            to_email = input("Enter recipient's email: ")
            subject = input("Enter email subject: ")
            body = input("Enter email body: ")
            if app.send_secure_email(to_email, subject, body):
                print("Secure email sent successfully!")
            else:
                print("Failed to send secure email.")
        
        elif choice == '2':
            print("\nChecking emails...")
            email_count = 0
            secure_count = 0
            for email in app.receive_emails():
                email_count += 1
                print(f"\nEmail {email_count}:")
                print(f"Subject: {email['subject']}")
                print(f"From: {email['sender']}")
                if email['is_secure']:
                    secure_count += 1
                    if email['decrypted']:
                        print("Secure Email:")
                        print(f"Body: {email['body']}")
                        print(f"Verified: {email['verified']}")
                    else:
                        print("Secure Email (Could not decrypt)")
                else:
                    print("Regular Email:")
                    print(f"Body: {email['body']}")
            
            if email_count == 0:
                print("No emails found.")
            else:
                print(f"\nTotal emails processed: {email_count}")
                print(f"Secure emails: {secure_count}")
        
        elif choice == '3':
            print("\nTrust List:")
            trust_list = app.trust_list
            if trust_list:
                for email in trust_list:
                    print(email)
            else:
                print("Trust list is empty.")
        
        elif choice == '4':
            print("Thank you for using the Secure Email Application!")
            break
        
        else:
            print("Invalid choice. Please try again.")


