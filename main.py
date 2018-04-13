# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# [START app]
from __future__ import print_function
import logging
import os

from numpy import array_split

import httplib2
import requests
import flask
import dateutil.parser
from datetime import datetime, timedelta
from threading import Thread
import time

# TODO: "3 days ago" - use https://github.com/miguelgrinberg/Flask-Moment
# TODO: i18n - use https://pythonhosted.org/Flask-Babel/

import google.oauth2.credentials
import google_auth_oauthlib.flow
import google_auth_oauthlib.helpers
import googleapiclient.discovery
from google.auth.transport.requests import AuthorizedSession

from oauth2client.client import GoogleCredentials

# google_auth_credentials = credentials_from_session(oauth2session)

from requests_toolbelt.adapters import appengine

SUBSCRIPTIONS_TIMEOUT = 4 * 60 * 60
UPLOADS_TIMEOUT = 30 * 60
UPLOADS_PLAYLIST_TIMEOUT = 0

appengine.monkeypatch()

# [START imports]
from flask import Flask, render_template, request
from flask_moment import Moment
from werkzeug.contrib.cache import GAEMemcachedCache

# [END imports]

# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "client_secret.json"

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection.
# see https://developers.google.com/identity/protocols/googlescopes
SCOPES = ['https://www.googleapis.com/auth/youtube.readonly']
API_SERVICE_NAME = 'youtube'
API_VERSION = 'v3'

# [START create_app]
app = Flask(__name__)
moment = Moment(app)
cache = GAEMemcachedCache()
# [END create_app]

# Replace this with a truly secret
# key. See http://flask.pocoo.org/docs/0.12/quickstart/#sessions.
app.secret_key = 'l\x1c.\xe6X\x9cq\xdb\x93w\xcc!\xf5]\x8d\x91\xb2\xfe|Y\xb6\xe4\x83\xd0'


@app.route('/')
def index():
    return render_template('home.html')


@app.route('/about')
def about():
    return render_template('about.html')

def read_uploadplaylist_from_channel(subscribed_channels_chunk, all_upload_playlists, youtube):
    cached_results = cache.get_many(*["uploadplaylist_" + channel for channel in subscribed_channels_chunk])

    cache_misses = []
    for i in range(len(subscribed_channels_chunk)):
        if cached_results[i] is None:
            cache_misses.append(subscribed_channels_chunk[i])
        else:
            all_upload_playlists.append(cached_results[i])

    uploads_playlist_result = youtube.channels().list(
        part='contentDetails',
        maxResults=len(subscribed_channels_chunk),
        id=",".join(cache_misses)).execute()

    for upload in uploads_playlist_result.get('items', []):
        cache.add("uploadplaylist_"+upload['id'], upload['contentDetails']['relatedPlaylists']['uploads'], UPLOADS_PLAYLIST_TIMEOUT)
        all_upload_playlists.append(upload['contentDetails']['relatedPlaylists']['uploads'])


def read_latest_videos_from_upload_playlist(playlist, all_new_videos, youtube):
    new_videos = cache.get('uploads_from_' + playlist)
    if new_videos is None:
        new_videos = youtube.playlistItems().list(part='snippet', playlistId=playlist, maxResults=50).execute().get('items', [])
        for video in new_videos:
            video['snippet']['publishedAt_parsed'] = dateutil.parser.parse(video['snippet']['publishedAt'])
        cache.add('uploads_from_' + playlist, new_videos, UPLOADS_TIMEOUT)

    new_videos = filter(lambda video: datetime.now(video['snippet']['publishedAt_parsed'].tzinfo)-timedelta(days=7) <= video['snippet']['publishedAt_parsed'] , new_videos)
    all_new_videos += new_videos
    pass


@app.route('/subs')
def show_all_subs():
    if 'credentials' not in flask.session:
        return flask.redirect('authorize')

    # Load credentials from the session.
    credentials = credentials_from_session()

    print("Credentials expiry: ", credentials.expiry)
    print("Credentials expired? ", credentials.expired)

    if credentials.expired:
        refresh_credentials(credentials)

    youtube = googleapiclient.discovery.build(
        API_SERVICE_NAME, API_VERSION, credentials=credentials)

    active_channel = read_active_channel(youtube)

    print("Active channel ID", active_channel['id'])
    subscribed_channel_ids, subscribed_channel_thumbnails = read_subscriptions(active_channel, youtube)

    all_upload_playlists = read_upload_playlists(subscribed_channel_ids, youtube)

    all_sorted_videos = read_latest_videos(all_upload_playlists, youtube)

    return render_template('subfeed.html',
                           videos=all_sorted_videos,
                           channel=active_channel,
                           thumbs=subscribed_channel_thumbnails)


def read_latest_videos(all_upload_playlists, youtube):
    # read latest videos from upload playlists
    all_new_videos = []
    collect_videos_threads = []
    for upload_playlist in all_upload_playlists:
        while len(collect_videos_threads) >= 50:
            for process in collect_videos_threads:
                process.join()
            collect_videos_threads = []
        process = Thread(args=[upload_playlist, all_new_videos, youtube],
                         target=read_latest_videos_from_upload_playlist)
        process.start()
        collect_videos_threads.append(process)
    for process in collect_videos_threads:
        process.join()
    all_sorted_videos = sorted(all_new_videos, reverse=True, key=lambda x: x['snippet']['publishedAt'])
    return all_sorted_videos


def read_upload_playlists(subscribed_channel_ids, youtube):
    # read upload playlists from subscribed channels
    collect_uploadplaylists_threads = []
    all_upload_playlists = []
    for subscribed_channels_chunk in array_split(subscribed_channel_ids, 1 + (len(subscribed_channel_ids) / 50)):
        subscribed_channels_chunk = subscribed_channels_chunk.tolist()

        process = Thread(args=[subscribed_channels_chunk, all_upload_playlists, youtube],
                         target=read_uploadplaylist_from_channel)
        process.start()
        collect_uploadplaylists_threads.append(process)
    for process in collect_uploadplaylists_threads:
        process.join()
    return all_upload_playlists


def read_subscriptions(active_channel, youtube):
    subscribed_channel_ids = cache.get('subs_for_' + active_channel['id'])
    subscribed_channel_thumbnails = cache.get('thumbs_for_' + active_channel['id'])
    if (subscribed_channel_ids is None) or (subscribed_channel_thumbnails is None):

        # cache miss!

        subscribed_channel_thumbnails = {}
        subscribed_channel_ids = []

        # read subscribed channels

        channels_request = youtube.subscriptions().list(
            mine=True,
            part='snippet',
            maxResults=50,
            fields='kind,etag,nextPageToken,prevPageToken,pageInfo,items/snippet/resourceId,items/snippet/title,items/snippet/thumbnails/medium/url'
        )

        while channels_request is not None:
            subscribed_channels_result = channels_request.execute()

            subscribed_channels = subscribed_channels_result.get('items', [])

            for subscribed_channel in subscribed_channels:
                channel_id = subscribed_channel['snippet']['resourceId']['channelId']
                subscribed_channel_ids.append(channel_id)
                subscribed_channel_thumbnails[channel_id] = subscribed_channel['snippet']['thumbnails']['medium']['url']

            channels_request = youtube.subscriptions().list_next(channels_request, subscribed_channels_result)

        cache.set('subs_for_' + active_channel['id'], subscribed_channel_ids,
                  timeout=SUBSCRIPTIONS_TIMEOUT)
        cache.set('thumbs_for_' + active_channel['id'], subscribed_channel_thumbnails,
                  timeout=SUBSCRIPTIONS_TIMEOUT)
    return subscribed_channel_ids, subscribed_channel_thumbnails


def read_active_channel(youtube):
    active_channel_response = youtube.channels().list(
        mine=True,
        part='snippet'
    ).execute()
    active_channel = active_channel_response.get('items')[0]
    return active_channel


def refresh_credentials(credentials):
    print("Credentials have been expired, refreshing")
    refresh_request = google.auth.transport.requests.Request(session=AuthorizedSession(credentials))
    credentials.refresh(refresh_request)
    save_credentials_to_session(credentials)


@app.route('/authorize')
def authorize():
    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)

    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    authorization_url, state = flow.authorization_url(
        # Enable offline access so that you can refresh an access token without
        # re-prompting the user for permission. Recommended for web server apps.
        access_type='offline',
        # Enable incremental authorization. Recommended as a best practice.
        include_granted_scopes='true',
        prompt='consent')

    # Store the state so the callback can verify the auth server response.
    flask.session['state'] = state

    return flask.redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
    # Specify the state when creating the flow in the callback so that it can
    # verified in the authorization server response.
    state = flask.session['state']

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)

    # Store credentials in the session.
    # ACTION ITEM: In a production app, you likely want to save these
    #              credentials in a persistent database instead.
    save_credentials_to_session(flow.credentials)

    return flask.redirect(flask.url_for('show_all_subs'))


def dump(obj):
    for attr in dir(obj):
        print("obj.%s = %r" % (attr, getattr(obj, attr)))


@app.route('/revoke')
def revoke():
    if 'credentials' not in flask.session:
        return ('You need to <a href="/authorize">authorize</a> before ' +
                'testing the code to revoke credentials.')

    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    revoke = requests.post('https://accounts.google.com/o/oauth2/revoke',
                           params={'token': credentials.token},
                           headers={'content-type': 'application/x-www-form-urlencoded'})

    status_code = getattr(revoke, 'status_code')
    if status_code == 200:
        return render_template('home.html', message='Credentials successfully revoked.')
    else:
        return render_template('home.html', message='An error occurred.')


@app.route('/clear')
def clear_credentials():
    if 'credentials' in flask.session:
        del flask.session['credentials']
    return render_template('home.html', message='Credentials have been cleared.')


def save_credentials_to_session(credentials):
    credentials.expiry = credentials.expiry - timedelta(hours=1)
    flask.session['credentials'] = credentials_to_dict(credentials)
    flask.session['token_expiry'] = credentials.expiry


def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
            }


def credentials_from_session():
    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])
    credentials.expiry = flask.session['token_expiry']
    return credentials


@app.errorhandler(500)
def server_error(e):
    # Log the error and stacktrace.
    logging.exception('An error occurred during a request.')
    return 'An internal error occurred.', 500

# [END app]
