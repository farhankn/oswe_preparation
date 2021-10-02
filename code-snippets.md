## Python Server

```
# taken from http://www.piware.de/2011/01/creating-an-https-server-in-python/
from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl

httpd = HTTPServer(('localhost', 4443), SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, certfile='/tmp/server.pem', server_side=True)
httpd.serve_forever()

```












## Upgrade to interacitve Shell

``` python -c ‘import pty;pty.spawn(“/bin/bash”)’ ```
    
export TERM=xterm #both this will enable clear and all
ctrl +Z (will put it in background)
stty raw -echo ( disable raw processing like ctrl+c and disable echo)
type fg and press enter
press enter twice.


