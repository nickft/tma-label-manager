#!/bin/sh
touch README NEWS
for DIR in config m4; do
   test -d $DIR || mkdir $DIR
done
autoreconf --force -I config -I m4 --install
