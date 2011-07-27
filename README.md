# goxsh

Mt. Gox Shell — a command-line frontend to the Mt. Gox Bitcoin Exchange

## Features

- Buy and sell bitcoins
- Specify buy/sell amounts in BTC or USD
- List and cancel orders
- Withdraw bitcoins
- Tow ways to authenticate with Mt. Gox
	1. Interactive authentication with no-echo password prompt — no need to store your credentials on disk
	2. Authentication via API-key and secret (see Usage->Login with API-key/Secret...)
- Display account balance
- Display ticker
- Calculate profitable short/long prices from an initial price
- Tab completion of commands
- Sequence multiple commands using semicolons
- Abort commands with SIGINT (ctrl-c on *nix) without exiting, if Mt. Gox is being slow
- Insert comments (# blah) e.g. for quick notes
- Personalize output of certain commands with different colors (see goxsh.cfg)
- Set configuration values and apply them within goxsh

## Requirements

- [Python](http://python.org/) 2.6 or a newer 2.* release.
- [PyCrypto](https://www.dlitz.net/software/pycrypto/) 2.0.1 or later.

## Usage

Run the script in a terminal window and type "help" to see the list of available commands.

### Login/Logout with username/password

1. Open config file (goxsh.cfg)
2. Change mode to "old" within the [authmode] section
3. Save and close config file
4. Run command "login your-mt-gox-username"
5. Enter your Mt. Gox password
6. Run command "logout" to logout

### Login with API-key/secret instead of username/password

Steps 1-10 apply only to first time usage of goxsh's api-login. If you have already
activated goxsh skip to step 11.

1. Open config file (goxsh.cfg)
2. Change mode to "api" within the [authmode] section
3. Save and close config file
4. Run goxsh.py
5. Set your username
	- Run command "set userauth username your-username"
	No need to use same username than the one used with Mt. Gox, it is just used
	to display if logged in by providing it to the shell's prompt when logged in.
6. Set the device name
	- Run command "set appauth devicename your-device-name"
	(it is recommended to use sth. similar to "YourComputersName_goxsh")
7. Reload config by running the command "reload"
8. Obtain activation key
	- Login to Mt. Gox by pointing your webbrowser to https://mtgox.com/users/login
	- Click on your username at the upper right
	- Go to section "Application access"
	- Opt in all rights you want to grant this application (granting all is recommended)
	- Copy the generated key to clipboard (key is valid for 5 minutes only!)
9. Run command "activate" with your activation key as argument ("activate your-key")
10. Enter password to encrypt your secret
	(it is recommended to use a different one than the one used with Mt. Gox!)
11. Run command "login"
12. Enter password to access encrypted secret

## License

Public domain. :)