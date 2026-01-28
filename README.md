About Samba mods
===========

- [x] Mod 1    // LDAP context refreshing

      Versions support:
        - [x] 4.22
        - [ ] 4.23
        - [ ] 4.24

---
This modification currently enables:

- Forcing LDAP user group membership updates and applying the updated user access context to an existing client session without requiring reconnection to the shared resource.

- Controlling the update frequency by reusing the winbind cache time directive in the configuration file.
  The value set for winbind cache time specifies the duration in seconds during which group membership is cached. After this interval expires, the group membership context is refreshed (only when discrepancies are detected). If the LDAP source is temporarily unavailable, the previous context is preserved.
  When winbind cache time is set to 0, the update mechanism is disabled.


About Samba
===========

Samba is the standard Windows interoperability suite of
programs for Linux and Unix.
Samba is Free Software licensed under the GNU General Public License and
the Samba project is a member of the Software Freedom Conservancy.
Since 1992, Samba has provided secure, stable and fast file and print services
for all clients using the SMB/CIFS protocol, such as all versions of DOS
and Windows, OS/2, Linux and many others.
Samba is an important component to seamlessly integrate Linux/Unix Servers and
Desktops into Active Directory environments. It can function both as a
domain controller or as a regular domain member.


For the AD DC implementation a full HOWTO is provided at:
      https://wiki.samba.org/index.php/Samba4/HOWTO

Community guidelines can be read at:
      https://wiki.samba.org/index.php/How_to_do_Samba:_Nicely

This software is freely distributable under the GNU public license, a
copy of which you should have received with this software (in a file
called COPYING).

-------

