# Shibboleth IdP v5: Wilma Authentication

[![License](http://img.shields.io/:license-mit-blue.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://travis-ci.org/mpassid/shibboleth-idp-authn-wilma.svg?branch=master)](https://travis-ci.org/mpassid/shibboleth-idp-authn-wilma)
[![Coverage Status](https://coveralls.io/repos/github/mpassid/shibboleth-idp-authn-wilma/badge.svg?branch=master)](https://coveralls.io/github/mpassid/shibboleth-idp-authn-wilma?branch=master)

## Overview

This module implements an authentication flow for [Shibboleth Identity Provider v3](https://wiki.shibboleth.net/confluence/display/IDP30/Home) that interacts with a [Wilma]
(https://help.starsoft.fi/?q=node/106) instance. The
module can be used for outsourcing the authentication to a Wilma instance instead of for instance 
prompting and validating the user credentials locally.

## Prerequisities and compilation

- Java 17+
- [Apache Maven 3](https://maven.apache.org/)

```
mvn package
```

After successful compilation, the _target_ directory contains _shibboleth-idp-authn-wilma-<version>.zip_.

## Deployment

After compilation, the module's JAR-files must be deployed to the IdP Web
application. Also, the module's authentication flow and its bean definitions must
be deployed to the IdP. Depending on the IdP installation, the module deployment may be achieved for instance 
with the following sequence:

```
unzip target/shibboleth-idp-authn-wilma-<version>.zip
cp shibboleth-idp-authn-wilma-<version>/edit-webapp/WEB-INF/lib/* /opt/shibboleth-idp/edit-webapp/WEB-INF/lib
cp -r shibboleth-idp-authn-wilma-<version>/flows/* /opt/shibboleth-idp/flows
cp shibboleth-idp-authn-wilma-<version>/conf/* /opt/shibboleth-idp/conf/authn
cd /opt/shibboleth-idp
sh bin/build.sh
```

The final command will rebuild the _war_-package for the IdP application.

The remote Wilma instance's MPASS endpoint and the shared secret must be configured in the file
_/opt/shibboleth-idp/flows/authn/Wilma/wilme-beans.xml_.

Finally, you will need to add the new authentication flow definition(s) to _/opt/shibboleth-idp/conf/authn/general-authn.xml_:

```
<bean id="authn/Wilma" parent="shibboleth.AuthenticationFlow"
            p:nonBrowserSupported="false" p:forcedAuthenticationSupported="true"/>
```

The flow definition must also be enabled via _idp.authn.flows_ variable in _/opt/shibboleth-idp/conf/idp.properties_.
