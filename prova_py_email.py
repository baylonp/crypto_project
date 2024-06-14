import smtplib
import sys

 
random_challenge = str(sys.argv[1])
username = str(sys.argv[2])

email_addr = str(sys.argv[3])

sender = 'verifica@anonforum.com'
receiver = email_addr

title = 'Challenge Verification'

body = 'Ciao '+ username+'\nEcco il tuo numero, inviacelo per verificare che sei umano :) \n'+ random_challenge 

email = f'''from: {sender}
to: {receiver}
subject: {title}

{body}'''

smtp = smtplib.SMTP(host='localhost', port=26)
smtp.sendmail(from_addr=sender, to_addrs=receiver, msg=email)


#print(n)



