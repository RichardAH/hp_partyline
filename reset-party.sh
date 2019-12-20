#!/bin/bash

nodes=3
sudo ./cluster-create-party.sh $nodes
WD=`pwd`
# Setup initial state data for all nodes but one.
for (( i=1; i<$nodes; i++ ))
do
    
    sudo mkdir -p ~/hpcore/hpcluster/node$i/statehist/0/data/
    pushd ~/hpcore/hpcluster/node$i/statehist/0/data/
    >party.table
    popd
    #sudo cp -r ~/Downloads/big.mkv ~/hpcore/hpcluster/node$i/statehist/0/data/

done
