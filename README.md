# Oauth-V1-Burp-Plugin


These jython files will automatically generate the Oauth V1 signature given the consumer_key, consumer_secret, access_token and access_token_secret and apply it to all requests.
  applies when the base url signature values are all in the URL, not POST body or in the HTTP Headers

Seperate scripts for GET and POST requests.
  GET request can be easily changed to DELETE
  POST request can be eaily changed to PUT

OAuth v1 signature generator:
https://web.archive.org/web/20160430150356/https://oauth.googlecode.com/svn/code/javascript/example/signature.html

TODO: combine scripts to automatically detect GET or POST method and create the signature automatically
