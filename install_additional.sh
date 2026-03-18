# add this line to your apt installs
sudo apt-get update
source .venv/bin/activate
sudo apt-get install -y osslsigncode default-jre unzip wget
pip3 install -U requests captcha pillow
