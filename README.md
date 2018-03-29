# App Engine Standard Flask Tutorial App

[![Open in Cloud Shell][shell_img]][shell_link]

[shell_img]: http://gstatic.com/cloudssh/images/open-btn.png
[shell_link]: https://console.cloud.google.com/cloudshell/open?git_repo=https://github.com/GoogleCloudPlatform/python-docs-samples&page=editor&open_in_editor=appengine/standard/flask/tutorial/README.md

This sample shows how to use [Flask](http://flask.pocoo.org/) to handle
requests, forms, templates, and static files on Google App Engine Standard.

Before running or deploying this application, install the dependencies using
[pip](http://pip.readthedocs.io/en/stable/):

    pip install -t lib -r requirements.txt

For more information, see the [App Engine Standard README](../../README.md)

# Run locally

```$
dev_appserver.py --env_var OAUTHLIB_INSECURE_TRANSPORT=1 .
```

# Documentation

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