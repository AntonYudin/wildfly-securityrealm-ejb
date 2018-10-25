# wildfly-securityrealm-ejb

## Overview
EJB Security Realm for Wildfly

This is an implementation of wildfly/elytron security realm that uses an EJB bean as a way
to authenticate and authorize a user.

The implementation uses JDNI lookup to locate a bean that must have a method called "authenticate"
that takes two parameters - identity and password.

The actual authentication and authorization may be implemented in a @Stateless bean that could
be much more flexible than standard wildfly security realms.

One could use JPA/hibernate to query the database for identities/passwords/groups and reuse
the same model that is used in the actual application. There would be no need to write separate
queries for "users/groups" tables.

Another use for the EJB Security Realm could be an LDAP implementation that is flexible enough
to work with any LDAP source including Active Directory. The @Stateless bean could use
javax.naming.directory to query the LDAP and implement the logic that is unique to this
specific source - recursive search for groups, location in the directory for the groups/users,
custom attributes for usernames, etc.

The main idea is to shift the implementation of the authentication and authorization logic from
a low level, wildfly version dependent code to a @Stateless bean that is part of the main
application.


## How to

Create a **@Stateless** session bean and find it's global JNDI path.
For example, a **@Stateless** bean with the name **MyAuthentication** that is part of an ejb module with the file name **myejbmodule.jar** which is part of an ear with the name **myproject.ear** will have a global JNDI path:

**java:global/myproject/myejbmodule/MyAuthentication**

Deploy the EJB security realm module into $wildflydir/modules directory.

Use setup-security-wildfly-example.cli file to add the realm configuration and http configuration to the standalone.xml.

In this file change **java:app/logic-1.0/LDAPAuthentication** to the path to your custom EJB authentication
bean. (line 16 in setup-security-wildfly-example.cli)

Change the **NAME-ldap** in the setup-security-wildfly-example.cli to the name of your security domain.

Make sure that wildfly security domain is correctly set in the jboss-app.xml or jboss-web.xml

```
<?xml version="1.0" encoding="UTF-8"?>
<jboss-app>
	<security-domain>NAME-ldap</security-domain>
</jboss-app>
```

