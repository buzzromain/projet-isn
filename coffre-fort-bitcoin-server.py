import socket
import ast
from Crypto.Hash import SHA512
import os
import mysql.connector
import binascii
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.bind(('', 15555))

def send_mail(mail, password): #Fonction d'envoie d'un mail 
	msg = MIMEMultipart()
	msg['From'] = 'Service de recuperation de Coffre-Fort'
	msg['To'] = '%s' % mail
	msg['Subject'] = 'Mot de passe de recuperation' 
	message = 'Hello,\nVotre mot de passe de recuperation : %s' % password
	msg.attach(MIMEText(message))
	mailserver = smtplib.SMTP('smtp.gmail.com', 587)
	mailserver.ehlo()
	mailserver.starttls()
	mailserver.ehlo()
	mailserver.login('recoveryvaultisn@gmail.com', 'eN4md/c3+d@y&1uaRi6mpU$BuHn?b7cmIF#to54f') #login, password
	mailserver.sendmail('recoveryvaultisn@gmail.com', '%s' % mail, msg.as_string())
	mailserver.quit()

def config_recovery_pwd(mail, favorite_music, favorite_movie, recovery_password): #Fonction de configuration de la recuperation de mot de passe
		initialPersonalData = mail + favorite_music + favorite_movie #On reunit les informations personnelles de l'utilisateur
		initialHash = SHA512.new(initialPersonalData.encode()).hexdigest()
		data = (mail, recovery_password, initialHash)
		try:
			cursor.execute("""INSERT INTO data (mail, password, hash) VALUES(%s, %s, %s)""", data) #On entre les donnees dans la base de donnees
			conn.commit()
			client.sendall("\nCoffre-fort de recuperation cree avec succes.\n") #On envoie une information au client
		except:
			client.sendall("\nCoffre-fort de recuperation deja cree.\n")
			conn.rollback()	
		finally:
			conn.close()
		
def recovery_pwd(mail, favorite_music, favorite_movie): #Fonction de recuperation de mot de passe
		inputPersonalData = mail + favorite_music + favorite_movie 
		inputHash = SHA512.new(inputPersonalData.encode()).hexdigest()
		initialHash = 0 #On initialise la variable initialHash
		cursor.execute("""SELECT hash FROM data WHERE mail = %s""", (mail,)) #On lit le hash de l'utilisateur a partir de son mail
		j = cursor.fetchall() 
		for i in j:
			initialHash = i[0] #On lit le hash initial 
		if initialHash == inputHash: #On compare les deux hash
			cursor.execute("""SELECT password FROM data WHERE hash = %s""", (inputHash,)) #On recupere le mot de passe de l'utilisateur
			j = cursor.fetchall()
			for i in j:
				password = i[0]
			
			send_mail(mail, password)#On envoie un mail a l'utilisateur
			client.sendall("\nNous vous avons envoye un mail contenant votre mot de passe de recuperation\n")
		elif initialHash == 0:
			client.sendall("\nVous n'avez pas cree de coffre-fort de recuperation avec ce mail.\n")
		elif initialHash != inputHash:
			client.sendall("\nVos donnees personnelles ne correspond pas avec celle enregistree. Utilisation du service impossible\n")

		conn.close()
#main
while True:
		conn = mysql.connector.connect(host="buzzromain.com", port=3307,user="web",password="ZbhTTi8YUcKfaryk", database="isn")
		cursor = conn.cursor()
		socket.listen(5)
		client, address = socket.accept()
		print("{} connected".format(address))
		userData = client.recv(255)
		userData = userData.decode() #On recupere les donnees en provenance du client
		userData = ast.literal_eval(userData)
		mode = userData['mode']
		mail = userData['mail']
		favorite_music = userData['favorite_music']
		favorite_movie = userData['favorite_movie']
		recovery_password = userData['password']
		if mode == 1:
			config_recovery_pwd(mail, favorite_music, favorite_movie, recovery_password)
		elif mode == 2:
			recovery_pwd(mail, favorite_music, favorite_movie)
print("Close")
client.close()
socket.close()