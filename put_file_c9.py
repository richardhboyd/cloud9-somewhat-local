#!/usr/bin/env python3

# Python Standard Library
import json
import os
import urllib.parse

# 3P Modules
import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
import click
import requests
import webbrowser

# Find a way for a user to specify their profile without having to change this file!
session = boto3.Session(profile_name='federate')

credentials = session.get_credentials()
creds = credentials.get_frozen_credentials()

REGION = session.region_name
# Find a way to infer this or create an environment!
ENVIRONMENT = ''
CHROME_PATH = "/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --new-window --incognito %s"


# We gotta SigV4 ALL THE THINGS!!!!
def make_signed_headers(method, url, data=None, params=None, headers=None):
    request = AWSRequest(method=method, url=url, data=data, params=params, headers=headers)
    SigV4Auth(creds, "cloud9", REGION).add_auth(request)
    return dict(request.headers)

def signed_request(method, url, data=None, params=None, headers=None):
    signed_headers = make_signed_headers(method=method, url=url, data=data, headers=headers)
    return requests.request(method=method, url=url, headers=signed_headers, data=data)

class Cloud9IDE():
    def _set_membership_settings(self):
        url = f"https://cloud9.{REGION}.amazonaws.com/"
        data = {
            "environmentId": self._environment_id,
            "settings": json.dumps(self._membership_settings)}
        headers = {
          'X-Amz-Target': 'AWSCloud9WorkspaceManagementService.UpdateMembershipSettings',
          'Content-Type': 'application/x-amz-json-1.1'
        }
        response = signed_request(method='POST', url=url, data=json.dumps(data), headers=headers)
        if response.status_code != 200:
            print(response.raw)
            print(response.status_code)
            print(response.reason)
            raise Exception(response.raw)
        return

    def _get_membership_settings(self):
        url = f"https://cloud9.{REGION}.amazonaws.com/"
        data = {"environmentId": self._environment_id}
        headers = {
          'X-Amz-Target': 'AWSCloud9WorkspaceManagementService.GetMembershipSettings',
          'Content-Type': 'application/x-amz-json-1.1'
        }
        response = signed_request(method='POST', url=url, data=json.dumps(data), headers=headers)
        if response.status_code == 200:
            self._membership_settings = json.loads(response.json()['settings'])

    def _set_file_context(self, file_name: str):
        self._membership_settings['tabs']['json()']['focus'] = file_name
        tab_names = []
        for entry in self._membership_settings['tabs']['json()']['nodes']:
            entry['active'] = False
            tab_names.append(entry['name'])
        i=0
        found_space = False
        while not found_space:
            if f"tab{i}" not in tab_names:
                found_space = True
            else:
                i = i + 1
        tab_name = f"tab{i}"
        new_node = {
            'type': 'tab',
            'name': tab_name,
            'path': f"/{file_name}",
            'className': [tab_name, 'focus', 'collab-connected'],
            'document': {
                'changed': False,
                'meta': {'timestamp': 1594489456022},
                'filter': True,
                'title': file_name,
                'tooltip': f"/{file_name}",
                'ace': {}
            },
            'editorType': 'ace',
            'active': True
        }
        self._membership_settings['tabs']['json()']['nodes'].append(new_node)
        self._set_membership_settings()

    def _get_credentials(self):
        url = f"https://cloud9.{REGION}.amazonaws.com/"
        data = {"environmentId": self._environment_id}
        headers = {
          'X-Amz-Target': 'AWSCloud9WorkspaceManagementService.CreateEnvironmentToken',
          'Content-Type': 'application/x-amz-json-1.1'
        }
        token = signed_request(method='POST', url=url, data=json.dumps(data), headers=headers)
        vfs_url=f"https://vfs-cloud9.{REGION}.console.aws.amazon.com/vfs/{self._environment_id}"
        headers = {
            'origin': f"https://{REGION}.console.aws.amazon.com",
            'content-type': 'application/json'
        }
        vfs_data = {'version': 13,'token': token.json()}
        y = requests.request(method="POST", url=vfs_url, headers=headers, data=json.dumps(vfs_data))
        return y.cookies, y.headers['x-authorization']

    def add_file(self, file_name: str):
        only_file = file_name.split("/")[-1]
        url = f"https://vfs-cloud9.{REGION}.console.aws.amazon.com/vfs/{self._environment_id}/environment/{only_file}"
        headers = {'x-authorization': self._auth_token, 'content-type': 'text/plain'}
        data = open(file_name,'rb').read()
        X = requests.put(url=url, data=data, headers=headers, cookies=self._cookies)
        self._set_file_context(only_file)
        return

    def open_window(self):
        # Federation expects the credentials to be formatted in a specific way, this is just shuffling them around.
        json_credentials = {
            "sessionId": creds.access_key,
            "sessionKey": creds.secret_key,
            "sessionToken": creds.token
        }
        environment_url=f'https://{REGION}.console.aws.amazon.com/cloud9/ide/{self._environment_id}'
        url_prefix = f"""https://signin.aws.amazon.com/federation?Action=getSigninToken&Session={urllib.parse.quote(json.dumps(json_credentials))}"""
        signin_token_response = requests.get(url_prefix)
        signin_link = f"""https://signin.aws.amazon.com/federation?Action=login&Destination={urllib.parse.quote(environment_url)}&SigninToken={signin_token_response.json()["SigninToken"]}"""
        webbrowser.get(CHROME_PATH).open(signin_link, new=1)

    def __init__(self, environment_id: str):
        self._environment_id = environment_id
        self._get_membership_settings()
        self._cookies, self._auth_token = self._get_credentials()

@click.command()
@click.option('--file-name', default="", type=str)
def hello(file_name: str):
    c9 = Cloud9IDE(ENVIRONMENT)
    if len(file_name) <= 1:
        print("short file name")
        print(c9._membership_settings)
    else:
        c9.add_file(file_name)
        c9.open_window()
    return

def main():
    return

if __name__ == "__main__":
    hello()
