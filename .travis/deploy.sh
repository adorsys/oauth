if [[ "$TRAVIS_TAG" =~ ^oauth-parent-[[:digit:].]+$ ]] then
  echo "RELEASE TAG -> publish $TRAVIS_TAG to mvn central"
  mvn deploy javadoc:javadoc gpg:sign -Prelease -DskipTests -B -U -Pwildfly
else
  echo "NO RELEASE TAG -> don't publish to mvn central"
  mvn package -U -Pwildfly
fi


