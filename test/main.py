import smtplib
import ssl

sender = "test@example.com"
receiver = "admin@e45g.org"
message = "Subject: C Server Test\n\nHello from Python with TLS!"

# Create a context that does not verify the certificate
# (Necessary for self-signed certs during local development)
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

try:
    # Connect to your server
    server = smtplib.SMTP("localhost", 2525)
    server.set_debuglevel(1)  # Prints the SMTP traffic to your terminal

    server.ehlo()            # Identify yourself
    if server.has_extn("starttls"):
        print("Starting TLS...")
        server.starttls(context=context) # This triggers the STARTTLS command in your C code
        server.ehlo()        # Re-identify over the encrypted connection

    server.sendmail(sender, receiver, message)
    print("Mail sent successfully!")
except Exception as e:
    print(f"Error: {e}")
finally:
    server.quit()
