#!/bin/sh

sudo apt-get install build-essential python-dev python-pip libffi-dev -y
pip install -r requirements.txt

# Requirements for SASS
sudo apt-get install ruby -y
sudo gem install sass bootstrap-sass compass

# SASS Modification Watching
# nohup compass watch CTFd/static/sass &
