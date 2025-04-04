#!/usr/bin/env bash

patchChangesTypes='fix|perf|refactor'
minorChangesTypes='feat'

function latestVersion() {
  git describe --tags --match 'v*' --abbrev=0
}

function aheadLatestVersion() {
  git describe --tags --match 'v*' --long | cut -d '-' -f2
}

function isPatch() {
  git --no-pager log --pretty="format:%s" HEAD..."$1" | grep -cE "^($patchChangesTypes)(\([[:alnum:]._-]+\))?:.*"
}

function isMinor() {
  git --no-pager log --pretty="format:%s" HEAD..."$1" | grep -cE "^($minorChangesTypes)(\([[:alnum:]._-]+\))?:.*"
}

function isMajor() {
  git --no-pager log --pretty="format:%s" HEAD..."$1" | grep -cE "(!):.*|BREAKING CHANGE"
}

function gitTag(){
  git tag "$1"
  echo "New version $1 tag created"
}

# ensure we have tags
git fetch --force --tags

rawVersion=$(latestVersion) || {
  git tag v0.0.1
  echo "New version v0.0.1 tag created"
  exit 0
}

version=${rawVersion:1}
patch=$(echo "$version" | cut -d '.' -f3)
minor=$(echo "$version" | cut -d '.' -f2)
major=$(echo "$version" | cut -d '.' -f1)

if [[ $(aheadLatestVersion) -eq 0 ]]; then
  echo "Already at the latest version tag, not doing anything"
  exit 0
fi

# check for major version change first
if [[ $(isMajor "$rawVersion") -gt 0 ]]; then
  nextVersion="v$((major+1)).0.0"
  gitTag $nextVersion

# check for minor version change second
elif [[ $(isMinor "$rawVersion") -gt 0 ]]; then
  nextVersion="v$major.$((minor+1)).0"
  gitTag $nextVersion

# finally, check for patch version change
elif [[ $(isPatch "$rawVersion") -gt 0 ]]; then
  nextVersion="v$major.$minor.$((patch+1))"
  gitTag $nextVersion

# nothing important has changed
else
  echo "No need for new tag"
fi
