#!/bin/bash

id=g$(git rev-parse --short=7 HEAD)
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
	id=$id+
fi

echo -n .$id
