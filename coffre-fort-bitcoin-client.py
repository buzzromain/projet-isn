#!/usr/bin/env python
# -*- coding: utf-8 -*-
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA512
import getpass
import os
import binascii
import sys
import ast
import socket 

if sys.version_info > (3, 0): #Sert a adapter le programme en fonction de la version de python 
    v = 3
else:
    v = 2
#On definit les constantes du programme
BLOCK_SIZE = 16 #Taille des blocks du chiffrement AES
vault_directory = os.path.dirname( __file__ )
hote = "buzzromain.com"
port = 15555

#Fonction
#Cette fonction permet d'ajouter des informations a la fin du texte pour que celui-ci soit compose de blocks de 16 octets chacun
#La fonction de chiffrement AES necessite de chiffrer un texte dont la taille est un multiple de 16 octets
def pad(data):
    length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    if v == 3:
        return data + (chr(length)*length).encode("utf-8")
    else : 
        data += chr(length)*length
        return data

def unpad(data):
    return data[:-ord(data[len(data)-1:])]

def get_recovery_form(): #Fonction qui affiche le formulaire de recuperation de mot de passe
    print("\nSaisissez vos donnees personnelles : \n")
    mail = raw_input("Adresse mail : ")
    favorite_music = raw_input("Musique preferee: ")
    favorite_movie = raw_input("Film prefere : ")
    return mail, favorite_music, favorite_movie

def check_password(pwd_input, pwd_check): #Fonction qui verifie si le mot de passe est correct
    if pwd_check == pwd_input.decode():
        return True
    else:
        return False

def create_recovery_vault(plaintext): #Fonction qui creer le coffre-fort de recuperation
        recovery_password = binascii.hexlify(Random.get_random_bytes(16)) #on genere le mot de passe aleatoirement en bytes que l'on transforme en hexadecimal avec binascii.hexlify()
        #en hexadecimal car c'est l'ideal pour le stockage, plus lisible,...
        ciphertext, p = encrypt(plaintext, recovery_password) #on recupere le texte chiffre de la fonction encrypt()
        #p correspond a pwd_check mais on s'en fout, j'etait oblige de le mettre sinon erreur
        vault = open(vault_directory + "/coffre_fort_de_recuperation.txt" , "w") #on creer le fichier
        vault.write(ciphertext) #on enregistre seulement le texte chiffre contrairement a toute a l heure on s'en fout de pwd_check car on suppose 
        #que le mot de passe qui va servir a deverouille ce coffre-fort de recuperation est vrai vu que l'on envoie par mail il ne peut qu'etre exact.
        vault.close()
        try:
            #---on se connecte au serveur--
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((hote, port))
            #--voir variable tout en haut du programme--
            mail, favorite_music, favorite_movie = get_recovery_form() #on appelle la fonction get_recovery_form qui ouvre le formulaire de recuperation
            #on enregistre ce que la fonction renvoie 
            userData = {'mail': mail, 'favorite_music': favorite_music, 'favorite_movie': favorite_movie, 'password': recovery_password, 'mode': 1}
            # on creer un dictionnaire des donnees personnelles. sous forme de dictionnaire car on ne peut qu'envoyer qu'une donnee au serveur 
            userData = str(userData).decode("utf-8") #on transforme le dictionnaire en chaine de caractere
            #on doit absolument envoyer une chaine de caractere au serveur
            #le serveur va transformer la chaine de caractere en dictionnaire
            #puis recuperer la valeur des variables, cad les donnees personnelles de l'utilisateur
            #voir le site info.blaisepascal.fr
            s.send(userData) #on envoie au serveur les donnees personnelles 
            print(s.recv(255)) #On affiche ce qu'envoie le serveur
            s.close() #on ferme la connexion
        except:
            print("Connexion impossible au serveur.")

def open_recovery_vault(): #Fonction qui ouvre le coffre-fort de recuperation
    vault = open(vault_directory + "/coffre_fort_de_recuperation.txt")
    ciphertext = vault.read()
    vault.close()
    mail, favorite_music, favorite_movie = get_recovery_form()
    try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((hote, port))
            mail, favorite_music, favorite_movie = get_form()
            userData = {'mail': mail, 'favorite_music': favorite_music, 'favorite_movie': favorite_movie, 'mode': 2}
            userData = str(userData).decode("utf-8")
            s.send(userData)
            print(s.recv(255)) #On affiche ce qu'envoie le serveur
            s.close()
            if v == 2:
                plaintext = raw_input("Votre mot de passe de récupération : ")
            else:
                plaintext = input("Votre mot de passe de récupération : ")
            plaintext = decrypt(ciphertext, password)
            return plaintext
    except:
        print("Cannot connect to the server.")


def create_main_vault(plaintext, password): #Fonction qui creer le coffre-fort principal, on prend le texte brute (plaintext) et le mot de passe pour chiffrer 
    ciphertext, pwd_check = encrypt(plaintext, password) #on chiffre plaintext (cle privee bitcoin) avec le mot de passe (variable password)
    #la fonction encrypt() renvoie le texte chiffre (ciphertext), et le pwd_check qui correspond au dernier 32 bits du mot de passe hashe s
    #ses deux variables vont etre enregistre dans le fichier coffre_fort.txt
    #ses deux variables vont etre utile lors du deverouillage car il s'agit du texte chiffre et de pwd_check qui permet de verifier si le mot de passe est bon 
    if os.path.exists(vault_directory + "/coffre_fort.txt") == True: #Si le coffre-fort existe deja
        print("\nVoulez-vous effacer le coffre-fort deja existant ?")
        print("1. Oui")
        print("2. Non")
        if v == 2:
            delVault = int(raw_input("Votre choix : "))
        else:
            delVault = int(input("Votre choix : "))
        if delVault == 1:
            vault = open(vault_directory + "/coffre_fort.txt", "w") #on cree le fichier
            vault.write("{'ciphertext': '%s', 'pwd_check': '%s'}" % (ciphertext, pwd_check.decode("utf-8"))) #on enregistre le texte chiffre et pwd_check dans le fichier sous forme 
            #petite precision .decode() permet de bien enregistrer la donnees sous forme de chaine de caracteres avec des lettres et pas des bits
            #de dictionnaire
            #regarde la partie dictionnaire sur le site info.blaisepascal.fr
            vault.close() #on ferme le fichier
            print("\nCoffre-fort cree avec succes")
        else:
            print("\nArret du programme")
    else:
        #on fait la meme chose qu'en haut
        vault = open(vault_directory + "/coffre_fort.txt", "w")
        vault.write("{'ciphertext': '%s', 'pwd_check': '%s'}" % (ciphertext, pwd_check.decode("utf-8")))
        vault.close()
        print("\nCoffre-fort cree avec succes")
    
def open_main_vault(password): #Fonction qui creer le coffre-fort principal
    vault = open(vault_directory + "/coffre_fort.txt")
    readVault = ast.literal_eval(vault.read())
    vault.close()
    plaintext = decrypt(readVault['ciphertext'], password, readVault['pwd_check'])
    if plaintext == False:
        return open_recovery_vault()
    else:
        return plaintext

def encrypt(plaintext, password): #Fonction de chiffrement du coffre-fort
    password_hash = SHA512.new(password.encode()).digest() #On genere le hash du mot de passe
    derived_key = password_hash[:32] #La cle derive correspond au 32 premiers bits 
    pwd_check = binascii.hexlify(password_hash[32:]) #La cle derive correspond au 32 derniers bits 
    iv = Random.get_random_bytes(16) #On genere un IV aleatoire pour la fonction AES
    cipher = AES.new(derived_key, AES.MODE_CBC, iv)
    if v == 3:
        plaintext = pad(plaintext.encode("utf-8"))
    else:
        plaintext = pad(plaintext)
    ciphertext = iv + cipher.encrypt(plaintext)
    ciphertext = binascii.hexlify(ciphertext).decode("utf-8")
    return ciphertext, pwd_check

def decrypt(ciphertext, password, pwd_check=None): #Fonction de dechiffrement de coffre-fort (que ce soit coffre-fort principal ou recuperation)
    password_hash = SHA512.new(password.encode()).digest()
    if pwd_check == None or check_password(pwd_check, binascii.hexlify(password_hash[32:])) == True:
        #Si pwd_check == None ca veut dire que l'on souhaite deverouiller le coffre-fort de recuperation 
        #Si check_password == True ca veut dire que le mot de passe est vrai, donc on deverouille le coffre-fort.
        #Dans les deux cas, on deverouille le coffre-fort (que ce soit principal ou recuperation)
        derived_key = password_hash[:32] #il s'agit de la cle de verouillage et deverouillage coffre-fort
        ciphertext = binascii.unhexlify(ciphertext) #On transforme le texte chiffre format hexadecimal en binaire pour etre adapte a ce que demande la fonction cipher.decrypt()
        iv = ciphertext[:BLOCK_SIZE] #IV c'est le blocs initial pour le deverouillage
        #iv correspond a un blocs soit les 16 premiers octets du texte chiffre
        cipher = AES.new(derived_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext[BLOCK_SIZE:])) #on unpad et decrypt le texte du 16 octets jusqu'au dernier 

        return plaintext #retourne le texte en clair (cad cle privee)
    else:
        return False #sinon on renvoie false qui signifie qu'on peut pas deverouille le coffre-fort car on a pas le bon mot de passe
#main
print("1. Configurer coffre-fort")
print("2. Acceder au coffre-fort")
if v == 2: 
    mainChoice = int(raw_input("Votre choix : "))
else:
    mainChoice = int(input("Votre choix : "))
if mainChoice == 1:
    password = getpass.getpass("\nChoisissez un mot de passe : ")
    if v == 2:
        plaintext = raw_input("Cle privee Bitcoin : ")
    else:
        plaintext = input("Cle privee Bitcoin : ")
    create_main_vault(plaintext, password) #On cree le coffre-fort principale
    create_recovery_vault(plaintext) #On cree le coffre-fort de recuperation
elif mainChoice == 2:
    password = getpass.getpass("\nSaisissez votre mot de passe : ")
    print("Cle privee Bitcoin : %s" % open_main_vault(password))

