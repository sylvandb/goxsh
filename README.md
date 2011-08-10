# goxsh

Mt. Gox Shell — a command-line frontend to the Mt. Gox Bitcoin Exchange

## Features

- Buy and sell bitcoins
- Specify buy/sell amounts in BTC or USD
- List and cancel orders
- Withdraw bitcoins
- Authentication via API-key and secret (see Usage->Login with API-key/secret)
- Display account balance
- Display ticker
- Display depth
- Calculate profitable short/long prices from an initial price
- Tab completion of commands
- Sequence multiple commands using semicolons
- Abort commands with SIGINT (ctrl-c on *nix) without exiting, if Mt. Gox is being slow
- Insert comments (# blah) e.g. for quick notes
- Personalize output of certain commands with different colors (see goxsh.cfg)
- Set configuration values and apply them within goxsh

## Requirements

- POSIX environment (GNU/Linux, BSD, Unix, cygwin, ...)
- [Python](http://python.org/) 2.6 or a newer 2.* release.
- [PyCrypto](https://www.dlitz.net/software/pycrypto/) 2.0.1 or later.

## Usage
Download goxsh.py AND goxsh.cfg, run the script in a terminal window and type "help" to see the list of available commands.

### Login/Logout with username/password

No longer supported

### Login with API-key/secret

Steps 1-7 apply only to first time usage of goxsh. If you have already activated goxsh skip to step 11.

1. Run goxsh.py
2. Set your username
	- Run command "set userauth username your-username".
	No need to use same username than the one used with Mt. Gox, it is just used
	to display if logged in by providing it to the shell's prompt when logged in.
3. Set the device name
	- Run command "set appauth devicename your-device-name"
	(it is recommended to use sth. similar to "YourComputersName_goxsh")
4. Reload config by running the command "reload"
5. Obtain activation key
	- Login to Mt. Gox by pointing your webbrowser to https://mtgox.com/users/login
	- Click on your username at the upper right
	- Go to section "Application access"
	- Opt in all rights you want to grant this application (granting all is recommended)
	- Copy the generated key to clipboard (key is valid for 5 minutes only!)
6. Run command "activate" with your activation key as argument ("activate your-key")
7. Enter password to encrypt your secret
	(it is recommended to use a different one than the one used with Mt. Gox!)
8. Run command "login"
9. Enter password to access encrypted secret

## License

Public domain. :)