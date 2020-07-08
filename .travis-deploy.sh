#!/usr/bin/env bash
set -e

LDL_API=cjhdev/wic_api.git

SSH_DIR=~/.ssh

# add_key(name, key)
add_key(){
    
    mkdir -p $SSH_DIR/$1
     
    echo $2 | tr '.' '\n' | sed 's/\\ / /g' > $SSH_DIR/$1/id_rsa
    
    chmod 600 $SSH_DIR/$1/id_rsa    
    
    echo "" >> $SSH_DIR/config
    echo "Host $1-repo"  >> $SSH_DIR/config
    echo "  HostName github.com" >> $SSH_DIR/config
    echo "  User git" >> $SSH_DIR/config
    echo "  IdentityFile $SSH_DIR/$1/id_rsa" >> $SSH_DIR/config  
    echo "" >> $SSH_DIR/config    
}

sudo apt-get update
sudo apt-get install -y doxygen graphviz

add_key api "$API_KEY"

# API documentation

git clone git@api-repo:$LDL_API ~/api

cd $TRAVIS_BUILD_DIR/doxygen && make BUILD_NUMBER=$TRAVIS_BUILD_NUMBER

rm -rf ~/api/docs/*
cp -r $TRAVIS_BUILD_DIR/doxygen/html/* ~/api/docs/

git -C ~/api add -A
git -C ~/api commit -m "update"
git -C ~/api push origin master
