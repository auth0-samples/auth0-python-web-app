#!/bin/bash

docker build -t auth0-python-web-01-login .
docker run --rm --env-file .env -p 10443:10443 -it auth0-python-web-01-login
