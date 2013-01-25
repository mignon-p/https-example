/* based on:
 * http://archives.seul.org/libevent/users/Mar-2012/binGP2R6ys0C_.bin
 * (which is a .c file despite the extension and mime type) */

#include <errno.h>

#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "https-common.h"
#include "openssl_hostname_validation.h"

#include <stdbool.h>

static struct event_base *base = 0;
static SSL_CTX *sctx = 0;

struct session
{
  int kind;
  int init;
  int port;
  struct evhttp_connection *c;
  struct bufferevent *bev;
  const char *host;
  const char *data;
  size_t data_size;
  char *result;
};

/* This callback is called when the request is finished */
static void request_finished (struct evhttp_request *req, void *arg)
{ const int errcode = EVUTIL_SOCKET_ERROR ();
  struct session * s = arg;
  const int code = req  ?  evhttp_request_get_response_code (req)  :  0;

  if (code != HTTP_OK)
    { fprintf (stderr, "code=%d ", code);
      if (s->kind == EVHTTP_REQ_POST)
        fprintf (stderr, " POST failed");
      else if (s->kind == EVHTTP_REQ_GET)
        fprintf (stderr, " GET failed");
      fprintf (stderr, "\n");
    }

  if (req)
    { struct evbuffer *buf = evhttp_request_get_input_buffer (req);
      evbuffer_add (buf, "", 1);    /* NUL-terminate the buffer */
      char *payload = (char *) evbuffer_pullup (buf, -1);

      s->result = strdup (payload);
    }
  else
    { unsigned long oslerr;
      bool printed_err = false;
      while ((oslerr = bufferevent_get_openssl_error (s->bev)))
        { char buf[128];
          ERR_error_string_n (oslerr, buf, sizeof (buf));
          printf ("%s\n", buf);
          printed_err = true;
        }
      if (! printed_err)
        printf ("socket error = %s (%d)\n",
                evutil_socket_error_to_string (errcode),
                errcode);
    }
}

static void launch_request (struct session *s)
{ struct evhttp_request *new_req;
  struct evhttp_connection *conn;
  struct bufferevent *bev = NULL;

  /* Create a new SSL connection from our SSL context */
  SSL *ssl = SSL_new (sctx);
  if (! ssl)
    die_most_horribly_from_openssl_error ("SSL_new");

  /* Now wrap the SSL connection in an SSL bufferevent */
  bev = bufferevent_openssl_socket_new (
                                        base, -1, ssl, BUFFEREVENT_SSL_CONNECTING,
                                          0
                                        | BEV_OPT_CLOSE_ON_FREE
                                        | BEV_OPT_DEFER_CALLBACKS
                                        );

  /* Newly-added function in libevent 2.1 which allows us to specify
   * our own bufferevent (e. g. one with SSL) when creating a new
   * HTTP connection.  Sorry, not available in libevent 2.0. */
  conn = evhttp_connection_base_bufferevent_new (
                                base, 0, bev, s->host, s->port);
  evhttp_connection_set_timeout (conn, 60);

#if 0
  /* Retries defaults to 0, which seems bad, since some of the evhttp
   * code seems to assume that a retry will happen:
   * http://archives.seul.org/libevent/users/Jan-2013/msg00051.html
   * So, let's set retries to 1, in order to get past that case. */
  evhttp_connection_set_retries (conn, 1);
#endif

  s->c = conn;
  s->bev = bev;

  new_req = evhttp_request_new (request_finished, s);
  struct evkeyvalq *output_headers =
    evhttp_request_get_output_headers (new_req);
  evhttp_add_header (output_headers, "Host", s->host);
  evhttp_add_header (output_headers, "Connection", "close");

  if (s->kind == EVHTTP_REQ_POST)
    evbuffer_add (evhttp_request_get_output_buffer (new_req),
                  s->data, s->data_size);

  int suc = evhttp_make_request (conn, new_req, s->kind, "/");
  if (suc != 0)
    error_exit ("evhttp_make_request returned %d\n", suc);
}

/* See http://archives.seul.org/libevent/users/Jan-2013/msg00039.html */
static int cert_verify_callback (X509_STORE_CTX *x509_ctx, void *arg)
{ const char *host = (const char *) arg;
  const char *res_str = "X509_verify_cert failed";
  HostnameValidationResult res = Error;

  /* This is the function that OpenSSL would call if we hadn't called
   * SSL_CTX_set_cert_verify_callback().  Therefore, we are "wrapping"
   * the default functionality, rather than replacing it. */
  int ok_so_far = X509_verify_cert (x509_ctx);

  X509 *server_cert = X509_STORE_CTX_get_current_cert (x509_ctx);

  if (ok_so_far)
    { res = validate_hostname (host, server_cert);

      switch (res)
        {
        case MatchFound:
          res_str = "MatchFound";
          break;
        case MatchNotFound:
          res_str = "MatchNotFound";
          break;
        case NoSANPresent:
          res_str = "NoSANPresent";
          break;
        case MalformedCertificate:
          res_str = "MalformedCertificate";
          break;
        case Error:
          res_str = "Error";
          break;
        default:
          res_str = "WTF!";
          break;
        }
    }

  char cert_str[256];
  X509_NAME_oneline (X509_get_subject_name (server_cert),
                     cert_str, sizeof (cert_str));

  if (res == MatchFound)
    { info_report ("https server '%s' has this certificate, "
                    "which looks good to me:\n%s\n",
                    host, cert_str);
      return 1;
    }
  else
    { error_report ("Got '%s' for hostname '%s' and certificate:\n%s\n",
                    res_str, host, cert_str);
      return 0;
    }
}

static char *client_do_post (const char *host, int port, const char *passcode)
{ struct session s1;

  memset (&s1, 0, sizeof(s1));

  /* An event base is the structure libevent uses for handling events */
  base = event_base_new ();
  if (! base)
    error_exit ("Couldn't create an event_base: exiting\n");

  /* An OpenSSL context holds data that new SSL connections will
   * be created from. */
  sctx = SSL_CTX_new (SSLv23_client_method ());
  if (! sctx)
    die_most_horribly_from_openssl_error ("SSL_CTX_new");

  /* Find the certificate authority (which we will use to
   * validate the server) and add it to the context. */
  SSL_CTX_load_verify_locations (sctx, "certificate-authorities.pem", NULL);

  SSL_CTX_set_verify (sctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_cert_verify_callback (sctx, cert_verify_callback, (void *) host);

  /* We must urlencode the passcode, in case it contains special
   * characters. */
  char *urlencoded_passcode = evhttp_uriencode (passcode, -1, false);
  char buf[256];
  evutil_snprintf (buf, sizeof (buf), "passcode=%s", urlencoded_passcode);
  s1.data = buf;
  s1.data_size = strlen (buf);
  free (urlencoded_passcode);

#if 1
  /* Sadly, "host" must currently be an address which resolves to an IPv4
   * address.  (e. g. on my machine, "localhost" resolves to "::1" in
   * addition to "127.0.0.1", and it picks the IPv6 first.)
   * http://article.gmane.org/gmane.comp.lib.libevent.user/2671
   */
  if (0 == strcmp (host, "localhost"))
    host = "127.0.0.1"; /* horribly ugly hack to avoid ::1 for localhost */
#endif

  s1.kind = EVHTTP_REQ_POST;
  s1.host = host;
  s1.port = port;

  launch_request (&s1);

  /* This handles events until the request is finished, and then
   * returns. */
  event_base_loop (base, 0);

  /* Free everything */
  evhttp_connection_free (s1.c);
  event_base_free (base);
  SSL_CTX_free (sctx);

  return s1.result;
}

static const char host[] = "localhost";

int main (int argc, char **argv)
{ common_setup ();              /* initialize OpenSSL */

  /* Send the passcode to the https server in a POST request. */
  char *result = client_do_post (host, COMMON_HTTPS_PORT, COMMON_PASSCODE);
  printf ("server said: %s\n", result);
  free (result);

  return EXIT_SUCCESS;
}
