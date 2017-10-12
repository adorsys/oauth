#!/usr/bin/env bash
set -e

TAG_PATTERN="^oauth-parent-([[:digit:]]+\.)+[[:digit:]]+$"

if [[ ${TRAVIS_TAG} =~ ${TAG_PATTERN} ]]; then
  echo "RELEASE TAG -> publish $TRAVIS_TAG to mvn central";
  mvn --settings .travis/settings.xml deploy -Prelease -DskipTests -B -U -Pwildfly;
else
  echo "NO RELEASE TAG -> don't publish to mvn central";
fi


