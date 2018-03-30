# allmysubs.com

YouTube is known for optimizing the subscription feed. Some users don't like
that and long for a chronologically ordered video list of all their subscriptions.

This is the source code for the website [allmysubs.com](https://allmysubs.com)

# Notes

Before running or deploying this application, install the dependencies using
[pip](http://pip.readthedocs.io/en/stable/):

    source env/bin/activate
    pip install -t lib -r requirements.txt

## Run locally

Disable https when developling locally:

    dev_appserver.py --env_var OAUTHLIB_INSECURE_TRANSPORT=1 .

## Documentation

* Getting Started with Flask on App Engine Standard Environment:
  https://cloud.google.com/appengine/docs/standard/python/getting-started/python-standard-env
* Using OAuth 2.0 for Web Server Applications: 
  https://developers.google.com/youtube/v3/guides/auth/server-side-web-apps
* YouTube API Reference
  https://developers.google.com/youtube/v3/docs/
* YouTube Data API Client Library for Python
  https://developers.google.com/api-client-library/python/apis/youtube/v3
* Fixing requests on Google App Engine
  https://toolbelt.readthedocs.io/en/latest/adapters.html#appengineadapter