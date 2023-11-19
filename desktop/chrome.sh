#!/bin/bash
# already try in
# ubuntu 20.04
# debian 11
apt update
apt install -y wget libappindicator1 libdbusmenu-glib4 libdbusmenu-gtk4 libindicator7 libpango1.0 gdebi-core gdebi
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
gdebi -n google-chrome-stable_current_amd64.deb

# run by command
# google-chrome-stable
# or
# google-chrome-stable --no-sandbox
