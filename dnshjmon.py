#
# dnshjmon.py
# written by corelanc0d3r
# www.corelan.be
#

import os, sys
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email import Encoders
from email.MIMEBase import MIMEBase
import socket



# some helper stuff
def getNow():
	return datetime.datetime.now().strftime("%Y%m%d-%H:%M:%S")

def showsyntax(args):
	print ""
	print " Usage: %s [arguments]" % args[0]
	print ""
	print " Optional arguments:"
	print "     -h                  : show help"
	print "     -c <configfile>     : full path to config file."
	print "                           Defaults to dnshjmon.conf in current folder"
	print "     -s <smtp configfile : full path to smtp config file."
	print "                           Defaults to dnshjmonsmtp.conf in current folder"
	print "     -mail               : Test e-mail configuration"
	print ""
	return


def showbanner():

	print """
     __                __     __                         
 .--|  |.-----..-----.|  |--.|__|.--------..-----..-----.
 |  _  ||     ||__ --||     ||  ||        ||  _  ||     |
 |_____||__|__||_____||__|__||  ||__|__|__||_____||__|__|
                            |___|                        
                        [ corelanc0d3r - www.corelan.be ]
 """	

	return


def check_port(host,port):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		s.connect((host,port))
		return True
	except:
		return False


# ----- classes -----

class MailConfig:

	""" 
	Class to manage SMTP email config
	"""

	serverinfo = {}

	def __init__(self,filename):
		self.filename = filename
		self.fullpath = os.path.join(os.path.dirname(os.path.realpath(__file__)),filename)

	def configFileExists(self):
		return os.path.isfile(self.fullpath)

	def readConfigFile(self):
		f = open(self.fullpath,"r")
		content = f.readlines()
		f.close()
		serverdata = {}
		thisid = ""
		for l in content:
			line = l.replace("\n","").replace("\r","")
			if line.startswith("[") and line.endswith("]"):
				# new config
				# if we already have a config, save it first
				if thisid != "" and len(serverdata) > 0 and not thisid in self.serverinfo:
					self.serverinfo[thisid] = serverdata
				thisid = line[1:-1]
				serverdata = {}
			if not line.startswith("#") and len(line) > 0 and "=" in line:
				lineparts = line.split("=")
				configparam = lineparts[0]
				if len(lineparts) > 1 and len(configparam) > 0 and len(line) > len(configparam):
					configval = line[len(configparam)+1:]
					serverdata[configparam] = configval
		# save the last one too
		if thisid != "" and len(serverdata) > 0 and not thisid in self.serverinfo:
			self.serverinfo[thisid] = serverdata

		return

	def writeConfigFile(self):
		filecontent = []
		for configid in self.serverinfo:
			thisdata = self.serverinfo[configid]
			filecontent.append("[%s]" % str(configid))
			filecontent += thisdata

		f = open(self.fullpath,"wb")
		for l in filecontent:
			f.write("%s\n" % l)
		f.close()
		print "[+] Saved new config file"
		return

	def initConfigFile(self):
		print "[+] Creating a new config file."
		i_server = ""
		i_port = 25
		i_timeout = 300
		i_auth = "no"
		i_user = ""
		i_pass = ""
		i_from = ""
		i_to = ""
		i_tls = "no"

		while True:
			i_server = raw_input('    > Enter smtp mail server IP or hostname: ')
			if not i_server == "":
				break

		while True:
			i_port = raw_input('    > Enter mail server port (default: 25): ')
			if not str(i_port) == "":
				try:
					i_port = int(i_port)
					break
				except:
					continue
			else:
				i_port = 25
				break

		while True:
			i_from = raw_input("    > Enter 'From' email address: ")
			if not i_from == "":
				break

		while True:
			i_to = raw_input("    > Enter 'To' email address: ")
			if not i_to == "":
				break

		while True:
			i_timeout = raw_input('    > Enter mail server timeout (in seconds, default: 300): ')
			if not str(i_timeout) == "":
				try:
					i_timeout = int(i_timeout)
					break
				except:
					continue
			else:
				i_timeout = 300
				break

		while True:
			i_auth = raw_input('    > Does server require authentication? (yes/no, default: no): ')
			i_auth = i_auth.lower()
			if i_auth == "":
				i_auth = "no"
			if i_auth in ["yes","no"]:
				break

		if i_auth == "yes":
			while True:
				i_user = raw_input('    > Username: ')
				if not i_user == "":
					break
			while True:
				i_pass = raw_input('    > Password: ')
				if not i_pass == "":
					break

		while True:
			i_tls = raw_input('    > Does server require/support STARTTLS ? (yes/no, default: no): ')
			i_tls = i_tls.lower()
			if i_tls == "":
				i_tls = "no"
			if i_tls in ["yes","no"]:
				break

		initserverdata = []
		initserverdata.append("server=%s" % i_server)
		initserverdata.append("port=%d" % i_port)
		initserverdata.append("from=%s" % i_from)
		initserverdata.append("to=%s" % i_to)
		initserverdata.append("timeout=%d" % i_timeout)
		initserverdata.append("auth=%s" % i_auth)
		initserverdata.append("user=%s" % i_user)
		initserverdata.append("pass=%s" % i_pass)
		initserverdata.append("tls=%s" % i_tls)
		
		self.serverinfo = {}
		self.serverinfo[i_server] = initserverdata
		self.writeConfigFile()
		return


class DNSConfig:

	""" 
	Class to manage DNS email config
	"""

	def __init__(configfile):
		self.configfile = configfile
		return

	def getConfig(self):
		return


class Mailer:

	"""
	Class to handle email notifications
	"""

	def __init__(self,smtpconfigfile):
		self.server = "127.0.0.1"
		self.timeout = 300
		self.port = 25
		self.to = "root@127.0.0.1"
		self.fromaddress = "root@127.0.0.1"
		self.login = ""
		self.password = ""
		self.requirelogin = False
		self.usetls = False

		# read the config file
		cEmailConfig = MailConfig(smtpconfigfile)
		cEmailConfig.readConfigFile()
		serverconfigs = cEmailConfig.serverinfo
		# connect to the first one that is listening
		print "[+] Config file appears to contain %d mail server definitions" % len(serverconfigs)
		for mailid in serverconfigs:
			thisconfig = serverconfigs[mailid]
			if "server" in thisconfig:
				self.server = thisconfig["server"]
			if "port" in thisconfig:
				self.port = int(thisconfig["port"])
			print "[+] Checking if %s:%d is reachable" % (self.server,self.port)
			if check_port(self.server,self.port):
				# fill out the rest and terminate the loop
				print "    Yup, port is open"
				if "timeout" in thisconfig:
					self.timeout = int(thisconfig["timeout"])
				if "auth" in thisconfig:
					if thisconfig["auth"] == "yes":
						self.requirelogin = True
					else:
						self.requirelogin = False
				if "user" in thisconfig:
					self.login = thisconfig["user"]
				if "pass" in thisconfig:
					self.password = thisconfig["pass"]
				if "tls" in thisconfig:
					if thisconfig["tls"] == "yes":
						self.usetls = True
					else:
						self.usetls = False
				if "to" in thisconfig:
					self.to = thisconfig["to"]
				if "from" in thisconfig:
					self.fromaddress = thisconfig["from"]
				break
			else:
				print "    Nope"
		return

	def sendmail(self,info,logfile,mailsubject="DNS Hijack Monitor Alert"):
		msg = MIMEMultipart()
		bodytext = "\n".join(x for x in info)
		logtext =  "\n".join(x for x in logfile)
		mailbody = MIMEText(bodytext, 'plain')
		msg.attach(mailbody)

		msg['Subject'] = '%s - %s' % (gethostname(),mailsubject)
		msg['From'] = self.fromaddress
		msg['To'] =  self.to

		if len(logfile) > 0:
			part = MIMEBase('application', "octet-stream")
			part.set_payload(logtext)
			Encoders.encode_base64(part)
			part.add_header('Content-Disposition', 'attachment; filename="dnshjmon.txt"')
			msg.attach(part)
		noerror = False
		thistimeout = 5
		while not noerror:
			try:
				print "[+] Connecting to %s on port %d" % (self.server,self.port)
				s = smtplib.SMTP(self.server,self.port,'minicase',self.timeout)
				print "[+] Connected"
				if self.usetls:
					print "[+] Issuing STARTTLS"
					s.starttls()
					print "[+] STARTTLS established"
				if self.requirelogin:
					print "[+] Authenticating"
					s.login(self.login,self.password)
					print "[+] Authenticated"
				print "[+] Sending email"
				s.sendmail( self.to, [self.to], msg.as_string())
				print "[+] Mail sent, disconnecting"
				s.quit()
				noerror = True
			except smtplib.SMTPServerDisconnected as e:
				print "     ** ERROR, Server disconnected unexpectedly"
				print "        This is probably okay"
				noerror = True
			except smtplib.SMTPResponseException as e:
				print "     ** ERROR Server returned %s : %s" % (str(e.smtp_code),e.smtp_error)
			except smtplib.SMTPSenderRefused as e:
				print "     ** ERROR Sender refused %s : %s" % (str(e.smtp_code),smtp_error)
			except smtplib.SMTPRecipientsRefused as e:
				print "     ** ERROR Recipients refused"
			except smtplib.SMTPDataError as e:
				print "     ** ERROR Server refused to accept the data"
			except smtplib.SMTPConnectError as e:
				print "     ** ERROR establishing connection to server"
			except smtplib.SMTPHeloError as e:
				print "     ** ERROR HELO Error"
			#except smtplib.SMTPAUthenticationError as e:
			#	print "     ** ERROR Authentication"
			except smtplib.SMTPException as e:
				print "     ** ERROR Sending email"
			except:
				print "     ** ERROR Unable to send email !"

			if not noerror:
				print "     I'll try again in %d seconds" % thistimeout
				time.sleep(thistimeout)
				if thistimeout < 1200:
					thistimeout += 5
		return



# ----- main routine ----- 
if __name__ == "__main__":

	mailconfigfile = ""
	dnsconfigfile = ""
	workingfolder = os.getcwd()

	showbanner()

	arguments = []
	if len(sys.argv) >= 2:
		arguments = sys.argv[1:]
	
	args = {}
	last = ""
	for word in arguments:
		if (word[0] == '-'):
			word = word.lstrip("-")
			args[word] = True
			last = word
		else:
			if (last != ""):
				if str(args[last]) == "True":
					args[last] = word
				else:
					args[last] = args[last] + " " + word

	if "h" in args:
		showsyntax(sys.argv)

	if "mail" in args:
		content = []
		mailhandler = Mailer()
		info = ['dnshjmon.py email test']
		mailhandler.sendmail(info,content,'Email test')
		sys.exit(0)


	if "c" in args:
		if type(args["c"]).__name__.lower() != "bool":
			dnsconfigfile = args["c"]

	if "s" in args:
		if type(args["s"]).__name__.lower() != "bool":
			smtpconfigfile = args["s"]
