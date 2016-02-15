#!/usr/bin/env python
#-*- coding: utf-8 -*-

from termcolor import colored
import argparse
import json
import requests
import codecs
import locale
import os
import sys
import ast

class Censys:

	def __init__(self, ip):

		self.API_URL = "https://www.censys.io/api/v1"
		self.UID = ""
		self.SECRET = ""
		self.ip = ip

	def search(self):

		pages = float('inf')
		page = 1

		while page <= pages:

			params = {'query' : self.ip, 'page' : page}
			res = requests.post(self.API_URL + "/search/ipv4", json = params, auth = (self.UID, self.SECRET))
			payload = res.json()


			for r in payload['results']:

				ip = r["ip"]
				proto = r["protocols"]
		
			
				#print '[%s] IP: %s - Protocols: %s' % (colored('*', 'red'), ip, proto)
				print '[%s] IP: %s' % (colored('*', 'red'), ip)	
				
				if '80/http' or '443/https' or '22/ssh' or '21/ftp' or '993/imaps' or '995/pop3s' or '110/pop3' or '143/imap' in proto:
					self.view(ip)

			pages = payload['metadata']['pages']
			page += 1

	def view(self, server):

		res = requests.get(self.API_URL + ("/view/ipv4/%s" % server), auth = (self.UID, self.SECRET))
		payload = res.json()		

		try:
			# ASN
			if 'asn' in payload['autonomous_system'].keys():
				print "[%s] ASN: %s" % (colored('#', 'green'), payload['autonomous_system']['asn'])
			print "------------------------------------Servizi-------------------------------------"
			# 80/http
			if 'title' in payload['80']['http']['get'].keys():
				print "[+] 80/http: %s" % payload['80']['http']['get']['title']
			if 'server' in payload['80']['http']['get']['headers'].keys():
				print "[+] 80/http: %s" % payload['80']['http']['get']['headers']['server']
			# 21/ftp
			if 'product' in payload['21']['ftp']['banner']['metadata'].keys():
				print "[+] 21/ftp: %s" % payload['21']['ftp']['banner']['metadata']['product']
			# 22/ssh
			if 'software_version' in payload['22']['ssh']['banner'].keys():
				print "[+] 22/ftp: %s" % payload['22']['ssh']['banner']['software_version']
			# 443/https
			if 'version' in payload['443']['https']['tls'].keys():
				print "[+] 443/https: %s %s" % (payload['443']['https']['tls']['version'], payload['443']['https']['tls']['cipher_suite']['name'])
			# 110/pop3-tls
			if "OK" in payload['110']['pop3']['starttls']['starttls']:
				print "[+] 110/pop3-tls: %s %s" % (payload['110']['pop3']['starttls']['tls']['version'], payload['110']['pop3']['starttls']['tls']['cipher_suite']['name'])
			# 110/pop3
			if "ERR" in payload['110']['pop3']['starttls']['starttls']:
				print "[+] 110/pop3: %s" % payload['110']['pop3']['starttls']['banner']
			# 143/imap-tls
			if "OK" in payload['143']['imap']['starttls']['starttls']:
				print "[+] 143/imap-tls: %s %s" % (payload['143']['imap']['starttls']['tls']['version'], payload['143']['imap']['starttls']['tls']['cipher_suite']['name'])
			# 993/imaps
			#if "OK" in payload['993']['imaps']['starttls']['starttls']:
				#print "[+] 993/imaps: %s" % payload['993']['imaps']['starttls']['tls']['version']
				#print "[+] 993/imaps: %s" % payload['993']['imaps']['starttls']['tls']['cipher_suite']['name']
			# 143/imap
			if "ERR" in payload['143']['imap']['starttls']['starttls']:
				print "[+] 110/imap: %s" % payload['110']['imap']['starttls']['banner']

		except Exception as error:
			print error
		print "---------------------------------------------------------------------------------"

parser = argparse.ArgumentParser(description = 'CENSYS.IO Web Server Search')
parser.add_argument('-f', '--find', help='CENSYS Search', required = True)


args = parser.parse_args()
ip = args.find

censys = Censys(ip)
censys.search()
