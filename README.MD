[![Build Status](https://travis-ci.org/adorsys/oauth.svg?branch=master)](https://travis-ci.org/adorsys/oauth)

OAUTH2 - Sorry documentation needs to be done...

# How to build

    mvn clean install -Pwildfly

# Test with jboss

```
# download jboss-eap-6.4.0.zip from http://developers.redhat.com/products/eap/download/

# install to local repository
$ mvn install:install-file -Dfile=jboss-eap-6.4.0.zip -DgroupId=org.jboss.as -DartifactId=jboss-eap -Dversion=6.4 -Dpackaging=zip

# run tests with profile jbossas-embedded
$ mvn clean install -P jbossas-embedded
```

# Release
- Check Javadocs errors:
```
$ mvn javadoc:javadoc
```

- Make Release in git:
> ./devops/release/release.sh <release version> <next version (without -SNAPSHOT)>

For example:
```
$ ./devops/release/release.sh 1.0 1.1
```

Afterwards, log in to [Sonatype nexus](https://oss.sonatype.org/) and click on "Close" and then "Release" for the staging repository ([as described here](http://central.sonatype.org/pages/releasing-the-deployment.html)).
