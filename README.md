# Lenses LDAP plugin template

When using Lenses with LDAP enabled and you want to customise the way user roles are returned, this library is the reference point.
 
The current implementation is matching Active Directory setup.

Once the library is available then it needs to be dropped into Lenses lib folder and 
the following configuration snippet should be added to Lenses configuration.  


```json
lenses.security.ldap.plugin.class= "com.landoop.lenses.security.ldap.ActiveDirectoryMemberOfPlugin"
lenses.security.ldap.plugin.group.extract.regex="(?i)CN=(\\w+),ou=ServiceGroups.*"
lenses.security.ldap.plugin.memberof.key= "memberOf"
lenses.security.ldap.plugin.person.name.key="sn"
```

### How it works

When implementing your custom LDAP user role retrieval you first need a dependency to our light library:

```json
  compile "com.landoop:lenses-ldap-plugin:$pluginVersion"
```

Once that is done all is required is to implement this interface:

```java


public interface LdapUserGroupsPlugin {
  /**
   * Initializes the plugin by providing the instance of configuration containing all the entries it requires
   *
   * @param config An instance of {@code com.typesafe.config.Config}. This entry will contain the value setup in Lenses
   *               under the key 'lenses.security.ldap.plugin'
   */
  void initialize(Config config);

  /***
   * Returns all the groups for the person entry represented by {@code ldapEntryIdentification}
   * @param ctx  The <code>DirContext</code> instance to perform an operation on.
   * @param ldapEntryIdentification The identification of the LDAP entry used to authenticate the supplied <code>DirContext</code>.
   * @param adminRoles The list of roles/groups allowing Lenses admin rights
   * @param writeRoles The list of roles/groups allowing Lenses write rights
   * @param readRoles The list of roles/groups allowing Lenses read rights
   * @param noDataRoles the list of roles/groups allowing Lenses nodata rights
   * @return An instance of {@link UserInfo}
   */
  UserInfo getUserInfo(DirContext ctx,
                       LdapEntryIdentification ldapEntryIdentification,
                       Set<String> adminRoles,
                       Set<String> writeRoles,
                       Set<String> readRoles,
                       Set<String> noDataRoles);
}

``` 

The ```initialize``` method is called by Lenses after the instance of your class is created. 
To let Lenses know you have to set this configuration entry:
```json
lenses.security.ldap.plugin.class= "com.landoop.lenses.security.ldap.ActiveDirectoryMemberOfPlugin"
``` 

Lenses will call ```initialize``` with an instance of ```Config``` delivering you all the sub-keys for ```lenses.security.ldap.plugin```.
Following the example above you will have these keys available: ```group.extract.regex```, ```memberof.key```, ```class``` and ```person.name.key```.

>  You determine which configuration keys you need and your class `initialize` method is responsible for validating that as well.  


After the user has been authenticated the ```getUserInfo``` will be called.  
This is where the bulk of your logic will go. The end result of this method call should be the roles for the user.

The sample is targetted at LDAP setups like this:

```json
dn: uid=jduke,ou=Users,dc=jboss,dc=org
objectClass: top
objectClass: person
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectclass: simulatedMicrosoftSecurityPrincipal
cn: jduke
sn: jduke
uid: jduke
userPassword: theduke
memberOf: cn=AdminR,ou=Groups,dc=jboss,dc=org
memberOf: cn=WriteR,ou=Groups,dc=jboss,dc=org
SAMACCOUNTNAME: jduke

```
### Build

The build is based on gradle. Make sure you have ```gradle``` if not just visit the [install](https://gradle.org/install/) webpage.

```bash
gradle clean build
```