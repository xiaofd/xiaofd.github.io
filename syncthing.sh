sudo apt-get update
sudo apt-get install -y apt-transport-https
# Add the "stable" channel to your APT sources:
echo "deb https://apt.syncthing.net/ syncthing stable" | sudo tee /etc/apt/sources.list.d/syncthing.list

# Add the release PGP keys:
curl -s https://syncthing.net/release-key.txt | sudo apt-key add -

# Increase preference of Syncthing's packages ("pinning")
printf "Package: *\nPin: origin apt.syncthing.net\nPin-Priority: 990\n" | sudo tee /etc/apt/preferences.d/syncthing

# Update and install syncthing:
sudo apt-get update
sudo apt-get -y install syncthing