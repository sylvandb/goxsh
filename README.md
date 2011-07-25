# goxsh

Mt. Gox Shell — a command-line frontend to the Mt. Gox Bitcoin Exchange

## Features

- Buy and sell bitcoins
- Specify buy/sell amounts in BTC or USD
- List and cancel orders
- Withdraw bitcoins
- Interactive authentication with no-echo password prompt — no need to store your credentials on disk
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

[Python](http://python.org/) 2.6 or a newer 2.* release.

## Usage

Run the script in a terminal window and type "help" to see the list of available commands.

## License

Public domain. :)