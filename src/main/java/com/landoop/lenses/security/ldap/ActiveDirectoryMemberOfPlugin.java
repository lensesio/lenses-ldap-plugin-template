package com.landoop.lenses.security.ldap;

import com.typesafe.config.Config;
import org.springframework.ldap.core.LdapEntryIdentification;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ActiveDirectoryMemberOfPlugin implements LdapUserGroupsPlugin {
  private String memberOfKey = null;
  private String groupExtractRegex = null;
  private String userName = null;

  @Override
  public void initialize(Config config) {
    memberOfKey = readString(config, "memberof.key", "memberOf");
    groupExtractRegex = readString(config, "group.extract.regex", "(?i)CN=(\\w+),ou=Groups.*");
    userName = readString(config, "person.name.key", "sn");
  }

  /**
   * Returns all the groups for the person entry represented by <code>ldapEntryIdentification</code>
   *
   * @param ctx                     the <code>DirContext</code> instance to perform an operation on.
   * @param ldapEntryIdentification the identification of the LDAP entry used to authenticate the supplied <code>DirContext</code>.
   * @param adminRoles              A list of LDAP roles/groups for which admin rights are given in Lenses.
   * @param writeRoles              A list of LDAP roles/groups for which 'write' rights are given in Lenses.
   * @param readRoles               A list of LDAP roles/groups for which 'read' rights are given in Lenses.
   * @param noDataRoles             A list of LDAP roles/groups for which 'nodata' rights are given in Lenses.
   * @return A set of Ldap groups/roles the person belongs to
   */
  @Override
  public UserInfo getUserInfo(DirContext ctx, LdapEntryIdentification ldapEntryIdentification, Set<String> adminRoles, Set<String> writeRoles, Set<String> readRoles, Set<String> noDataRoles) {
    final String[] attributesToReturn = new String[]{memberOfKey, userName};
    try {
      Attributes allAttributes = ctx.getAttributes(ldapEntryIdentification.getRelativeName(), attributesToReturn);

      final Set<LensesRoles> roles = new HashSet<>();
      final Pattern groupExtract = Pattern.compile(groupExtractRegex);
      final NamingEnumeration<?> namings = allAttributes.get(memberOfKey).getAll();
      while (namings.hasMore()) {
        final String entry = namings.next().toString();
        final Matcher matcher = groupExtract.matcher(entry);
        if (matcher.find()) {
          final String group = matcher.group(1).toLowerCase();
          if (adminRoles.contains(group)) {
            roles.add(LensesRoles.ADMIN);
            roles.add(LensesRoles.WRITE);
            roles.add(LensesRoles.READ);
            roles.add(LensesRoles.NODATA);
          } else if (writeRoles.contains(group)) {
            roles.add(LensesRoles.WRITE);
            roles.add(LensesRoles.READ);
            roles.add(LensesRoles.NODATA);
          } else if (readRoles.contains(group)) {
            roles.add(LensesRoles.READ);
            roles.add(LensesRoles.NODATA);
          } else if (noDataRoles.contains(group)) {
            roles.add(LensesRoles.NODATA);
          }
        }
      }

      final Attribute name = allAttributes.get(userName);
      String userFullName = null;
      if (name != null) {
        userFullName = name.get().toString();
      }
      return new UserInfo(userFullName, roles);
    } catch (NamingException e) {
      throw new RuntimeException("Could not retrieve user roles for " + ldapEntryIdentification.getAbsoluteName(), e);
    }
  }

  /**
   * Reads the key from the configuration as a {@code String}. If the key is not provided it returns the default value;
   *
   * @param config       The instance of {@link Config}
   * @param key          The entry to look for in the {@code config}
   * @param defaultValue The value to return if the key is not present.
   * @return The value of the key if it exists; {@code defaultValue} otherwise.
   */
  private static String readString(Config config, String key, String defaultValue) {
    return get(config, key, defaultValue, config::getString);
  }

  /**
   * Helper method to read an entry from {@code Config}
   *
   * @param config Instance of {@link Config}
   * @param key The entry to look for
   * @param defaultValue The value to return if the entry is not found
   * @param extractor A function to convert from the configuration entry to the target type T.
   * @param <T>
   * @return An instance of {@link T} if the key is found; otherwise {@code defaultValue}
   */
  private static <T> T get(Config config, String key, T defaultValue, Function<String, T> extractor) {
    if (config.hasPath(key))
      return extractor.apply(key);
    return defaultValue;
  }
}

