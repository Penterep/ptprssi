[![penterepTools](https://www.penterep.com/external/penterepToolsLogo.png)](https://www.penterep.com/)


## PTPRSSI - Path-Relative Style Sheet Import Testing Tool

ptprssi is a tool that tests domains for path relative style sheet import vulnerabilities. <br />
This tool utilizes threading for fast parallel domain testing.

## Installation
```
pip install ptprssi
```

## Adding to PATH
If you're unable to invoke the script from your terminal, it's likely because it's not included in your PATH. You can resolve this issue by executing the following commands, depending on the shell you're using:

For Bash Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.bashrc
source ~/.bashrc
```

For ZSH Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.zshrc
source ~/.zshrc
```

## Usage examples
```
ptprssi -u https://www.example.com/
ptprssi -l domainList.txt
```

## Options
```
-u  --url         <url>           Connect to URL
-l  --list        <list>          Test list of domains
-p  --proxy       <proxy>         Set proxy (e.g. http://127.0.0.1:8080)
-T  --timeout     <timeout>       Set timeout (default 10s)
-H  --headers     <header:value>  Set Header(s)
-a  --user-agent  <agent>         Set User-Agent
-c  --cookie      <cookie>        Set Cookie(s)
-t  --threads     <threads>       Set threads count
-r  --redirects                   Follow redirects (default False)
-C  --cache                       Cache HTTP communication (load from tmp in future)
-v  --version                     Show script version and exit
-h  --help                        Show this help message and exit
-j  --json                        Output in JSON format
```

## Dependencies
```
ptlibs
bs4
lxml
```

## License

Copyright (c) 2024 Penterep Security s.r.o.

ptprssi is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

ptprssi is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with ptprssi. If not, see https://www.gnu.org/licenses/.

## Warning

You are only allowed to run the tool against the websites which
you have been given permission to pentest. We do not accept any
responsibility for any damage/harm that this application causes to your
computer, or your network. Penterep is not responsible for any illegal
or malicious use of this code. Be Ethical!