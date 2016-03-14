/* Derived from sample/http-server.c in libevent source tree.
 * That file does not have a license notice, but generally libevent
 * is under the 3-clause BSD.
 *
 * Plus, some additional inspiration from:
 * http://archives.seul.org/libevent/users/Jul-2010/binGK8dlinMqP.bin
 * (which is a .c file despite the extension and mime type) */

/*
  A trivial https webserver using Libevent's evhttp.

  This is not the best code in the world, and it does some fairly stupid stuff
  that you would never want to do in a production webserver. Caveat hackor!

 */

#include "https-common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#ifndef S_ISDIR
#define S_ISDIR(x) (((x) & S_IFMT) == S_IFDIR)
#endif
#else
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>

#ifdef EVENT__HAVE_NETINET_IN_H
#include <netinet/in.h>
# ifdef _XOPEN_SOURCE_EXTENDED
#  include <arpa/inet.h>
# endif
#endif

#ifdef _WIN32
#define stat _stat
#define fstat _fstat
#define open _open
#define close _close
#define O_RDONLY _O_RDONLY
#endif

unsigned short serverPort = COMMON_HTTPS_PORT;

/* Instead of casting between these types, create a union with all of them,
 * to avoid -Wstrict-aliasing warnings. */
typedef union
{ struct sockaddr_storage ss;
  struct sockaddr sa;
  struct sockaddr_in in;
  struct sockaddr_in6 i6;
} sock_hop;


/* This callback gets invoked when we get any http request that doesn't match
 * any other callback.  Like any evhttp server callback, it has a simple job:
 * it must eventually call evhttp_send_error() or evhttp_send_reply().
 */
static void
send_document_cb (struct evhttp_request *req, void *arg)
{ struct evbuffer *evb = NULL;
  const char *uri = evhttp_request_get_uri (req);
  struct evhttp_uri *decoded = NULL;

  if (evhttp_request_get_command (req) == EVHTTP_REQ_GET)
    {
      struct evbuffer *buf = evbuffer_new();
      if (buf == NULL) return;
      evbuffer_add_printf(buf, "Requested: %s\n", uri);
      evhttp_send_reply(req, HTTP_OK, "OK", buf);
      return;
    }

  /* We only handle POST requests. */
  if (evhttp_request_get_command (req) != EVHTTP_REQ_POST)
    { evhttp_send_reply (req, 200, "OK", NULL);
      return;
    }

  printf ("Got a POST request for <%s>\n", uri);

  /* Decode the URI */
  decoded = evhttp_uri_parse (uri);
  if (! decoded)
    { printf ("It's not a good URI. Sending BADREQUEST\n");
      evhttp_send_error (req, HTTP_BADREQUEST, 0);
      return;
    }

  /* Decode the payload */
  struct evkeyvalq kv;
  memset (&kv, 0, sizeof (kv));
  struct evbuffer *buf = evhttp_request_get_input_buffer (req);
  evbuffer_add (buf, "", 1);    /* NUL-terminate the buffer */
  char *payload = (char *) evbuffer_pullup (buf, -1);
  if (0 != evhttp_parse_query_str (payload, &kv))
    { printf ("Malformed payload. Sending BADREQUEST\n");
      evhttp_send_error (req, HTTP_BADREQUEST, 0);
      return;
    }

  /* Determine peer */
  char *peer_addr;
  ev_uint16_t peer_port;
  struct evhttp_connection *con = evhttp_request_get_connection (req);
  evhttp_connection_get_peer (con, &peer_addr, &peer_port);

  /* Extract passcode */
  const char *passcode = evhttp_find_header (&kv, "passcode");
  char response[256];
  evutil_snprintf (response, sizeof (response),
                   "Hi %s!  I %s your passcode.\n", peer_addr,
                   (0 == strcmp (passcode, COMMON_PASSCODE)
                    ?  "liked"
                    :  "didn't like"));
  evhttp_clear_headers (&kv);   /* to free memory held by kv */

  /* This holds the content we're sending. */
  evb = evbuffer_new ();

  evhttp_add_header (evhttp_request_get_output_headers (req),
                     "Content-Type", "application/x-yaml");
  evbuffer_add (evb, response, strlen (response));

  evhttp_send_reply (req, 200, "OK", evb);

  if (decoded)
    evhttp_uri_free (decoded);
  if (evb)
    evbuffer_free (evb);
}

/**
 * This callback is responsible for creating a new SSL connection
 * and wrapping it in an OpenSSL bufferevent.  This is the way
 * we implement an https server instead of a plain old http server.
 */
static struct bufferevent* bevcb (struct event_base *base, void *arg)
{ struct bufferevent* r;
  SSL_CTX *ctx = (SSL_CTX *) arg;

  r = bufferevent_openssl_socket_new (base,
                                      -1,
                                      SSL_new (ctx),
                                      BUFFEREVENT_SSL_ACCEPTING,
                                      BEV_OPT_CLOSE_ON_FREE);
  return r;
}

static void server_setup_certs (SSL_CTX *ctx,
                                const char *certificate_chain,
                                const char *private_key)
{ info_report ("Loading certificate chain from '%s'\n"
               "and private key from '%s'\n",
               certificate_chain, private_key);

  if (1 != SSL_CTX_use_certificate_chain_file (ctx, certificate_chain))
    die_most_horribly_from_openssl_error ("SSL_CTX_use_certificate_chain_file");

  if (1 != SSL_CTX_use_PrivateKey_file (ctx, private_key, SSL_FILETYPE_PEM))
    die_most_horribly_from_openssl_error ("SSL_CTX_use_PrivateKey_file");

  if (1 != SSL_CTX_check_private_key (ctx))
    die_most_horribly_from_openssl_error ("SSL_CTX_check_private_key");
}

static int serve_some_http (void)
{ struct event_base *base;
  struct evhttp *http;
  struct evhttp_bound_socket *handle;

#ifdef _WIN32
  WSADATA WSAData;
  WSAStartup (0x101, &WSAData);
#endif

  base = event_base_new ();
  if (! base)
    { fprintf (stderr, "Couldn't create an event_base: exiting\n");
      return 1;
    }

  /* Create a new evhttp object to handle requests. */
  http = evhttp_new (base);
  if (! http)
    { fprintf (stderr, "couldn't create evhttp. Exiting.\n");
      return 1;
    }

  SSL_CTX *ctx = SSL_CTX_new (SSLv23_server_method ());
  SSL_CTX_set_options (ctx,
                       SSL_OP_SINGLE_DH_USE |
                       SSL_OP_SINGLE_ECDH_USE |
                       SSL_OP_NO_SSLv2);

  /* Cheesily pick an elliptic curve to use with elliptic curve ciphersuites.
   * We just hardcode a single curve which is reasonably decent.
   * See http://www.mail-archive.com/openssl-dev@openssl.org/msg30957.html */
  EC_KEY *ecdh = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
  if (! ecdh)
    die_most_horribly_from_openssl_error ("EC_KEY_new_by_curve_name");
  if (1 != SSL_CTX_set_tmp_ecdh (ctx, ecdh))
    die_most_horribly_from_openssl_error ("SSL_CTX_set_tmp_ecdh");

  /* Find and set up our server certificate. */
  const char *certificate_chain = "server-certificate-chain.pem";
  const char *private_key = "server-private-key.pem";
  server_setup_certs (ctx, certificate_chain, private_key);

  /* This is the magic that lets evhttp use SSL. */
  evhttp_set_bevcb (http, bevcb, ctx);

  /* This is the callback that gets called when a request comes in. */
  evhttp_set_gencb (http, send_document_cb, NULL);

  /* Now we tell the evhttp what port to listen on */
  handle = evhttp_bind_socket_with_handle (http, "0.0.0.0", serverPort);
  if (! handle)
    { fprintf (stderr, "couldn't bind to port %d. Exiting.\n",
               (int) serverPort);
      return 1;
    }

  { /* Extract and display the address we're listening on. */
    sock_hop ss;
    evutil_socket_t fd;
    ev_socklen_t socklen = sizeof (ss);
    char addrbuf[128];
    void *inaddr;
    const char *addr;
    int got_port = -1;
    fd = evhttp_bound_socket_get_fd (handle);
    memset (&ss, 0, sizeof(ss));
    if (getsockname (fd, &ss.sa, &socklen))
      { perror ("getsockname() failed");
        return 1;
      }
    if (ss.ss.ss_family == AF_INET)
      { got_port = ntohs (ss.in.sin_port);
        inaddr = &ss.in.sin_addr;
      }
    else if (ss.ss.ss_family == AF_INET6)
      { got_port = ntohs (ss.i6.sin6_port);
        inaddr = &ss.i6.sin6_addr;
      }
    else
      { fprintf (stderr, "Weird address family %d\n", ss.ss.ss_family);
        return 1;
      }
    addr = evutil_inet_ntop (ss.ss.ss_family, inaddr, addrbuf,
                             sizeof (addrbuf));
    if (addr)
      printf ("Listening on %s:%d\n", addr, got_port);
    else
      { fprintf (stderr, "evutil_inet_ntop failed\n");
        return 1;
      }
  }

  event_base_dispatch (base);

  /* not reached; runs forever */

  return 0;
}

int main (int argc, char **argv)
{ common_setup ();              /* Initialize OpenSSL */

  if (argc > 1) {
    char *end_ptr;
    long lp = strtol(argv[1], &end_ptr, 0);
    if (*end_ptr) {
      fprintf(stderr, "Invalid integer\n");
      return -1;
    }
    if (lp <= 0) {
      fprintf(stderr, "Port must be positive\n");
      return -1;
    }
    if (lp >= USHRT_MAX) {
      fprintf(stderr, "Port must fit 16-bit range\n");
      return -1;
    }

    serverPort = (unsigned short)lp;
  }

  /* now run http server (never returns) */
  return serve_some_http ();
}
