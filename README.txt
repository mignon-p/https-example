ppelletier@chives:~/src/https-example$ uname -a
Linux chives 2.6.32-34-generic #77-Ubuntu SMP Tue Sep 13 19:39:17 UTC 2011 x86_64 GNU/Linux

start the server:

ppelletier@chives:~/src/https-example$ ./https-server
Using OpenSSL version "OpenSSL 1.0.1c 10 May 2012"
and libevent version "2.1.2-alpha-dev"
Loading certificate chain from 'server-certificate-chain.pem'
and private key from 'server-private-key.pem'
Listening on 0.0.0.0:8421

run the client... it works!

ppelletier@chives:~/src/https-example$ ./https-client
Using OpenSSL version "OpenSSL 1.0.1c 10 May 2012"
and libevent version "2.1.2-alpha-dev"
https server 'localhost' has this certificate, which looks good to me:
/C=US/ST=CA/L=Los Angeles/O=Oblong Industries/OU=Plasma/CN=localhost
server said: Hi 127.0.0.1!  I liked your passcode.

do the same thing with curl instead of with the client:

ppelletier@chives:~/src/https-example$ curl -k -d 'passcode=R23' https://localhost:8421/
Hi 127.0.0.1!  I liked your passcode.

Now, change the "#if 1" on line 214 of https-client.c to "#if 0", to
get rid of the special hack that turns "localhost" into "127.0.0.1",
in order to avoid IPv6.  Here's what happens:

ppelletier@chives:~/src/https-example$ ./https-client
Using OpenSSL version "OpenSSL 1.0.1c 10 May 2012"
and libevent version "2.1.2-alpha-dev"
code=0  POST failed
server said:

Next, change the "#if 0" on line 100 of https-client.c to "#if 1", to
enable retries:

ppelletier@chives:~/src/https-example$ ./https-client
Using OpenSSL version "OpenSSL 1.0.1c 10 May 2012"
and libevent version "2.1.2-alpha-dev"
[warn] Epoll ADD(1) on fd 7 failed.  Old events were 0; read change was 1 (add); write change was 0 (none): Bad file descriptor
[warn] Epoll ADD(4) on fd 7 failed.  Old events were 0; read change was 0 (none); write change was 1 (add): Bad file descriptor
code=0  POST failed
socket error = Bad file descriptor (9)
server said: (null)
