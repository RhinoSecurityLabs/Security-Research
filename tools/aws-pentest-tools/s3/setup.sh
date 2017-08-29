#!/usr/bin/env bash

git clone https://github.com/aboul3la/Sublist3r.git
which pip3
if [ $? -ne 0 ]
then
    echo "Installing python3-pip..."
    sudo apt-get install -y python3-pip
fi

# Fix imports for python3 Sublist3r ran from buckethead.
sed -i 's/from subbrute import/from Sublist3r.subbrute import/g' Sublist3r/sublist3r.py

sudo pip3 install -r Sublist3r/requirements.txt

# Check for aws
which aws
if [ $? -ne 0 ]
then
    echo "Installing awscli..."
    sudo apt-get install -y awscli
fi

aws configure

echo "All done!"