# Client certificate (mTLS) download

This page describes how SafeRoom can download its list from a server that requires a TLS client certificate. The design target is the Okta Device Trust certificate. The certificate identifies the managed device to the list server.

This path is not tested. The project has no Okta environment. The bearer-token path and the local-file path are tested.

## Policy

```xml
<key>ListURL</key>
<string>https://intel.example.com/saferoom/list.txt</string>
<key>Auth</key>
<dict>
    <key>Type</key>
    <string>clientCertificate</string>
    <key>IdentityIssuerContains</key>
    <string>Okta</string>
</dict>
```

## What the extension does

1. The server asks for a client certificate during the TLS handshake.
2. The extension searches the keychains that it can see for identities. An identity is a certificate with its private key.
3. It takes the first identity whose subject contains `IdentitySubjectContains` and whose issuer contains `IdentityIssuerContains`. The comparison ignores case. A filter that is not set matches all identities.
4. It logs the subject and issuer of the identity it uses, and presents it.

If no identity matches, the extension logs the number of identities it found and cancels the download. The current list stays in use.

## Open risks

The extension runs as root. Root sees the System keychain, but not the login keychain of the signed-in user. If the Okta certificate is in the user's login keychain, the extension does not find it.

The private key can have an access control list. The key can be in the Secure Enclave, with only Okta Verify allowed to use it. In that case, a TLS handshake from the extension fails, even when the extension finds the certificate.

To find out, run one test on a managed Mac. Set the policy above, start the proxy, and read the `list` log category. The log shows one of three results: the certificate in use, "no keychain identity matches", or a TLS error.

## Fallback design

If the extension cannot use the certificate, the SafeRoom app can download the list instead. The app runs as the signed-in user, and that user can see the login keychain.

The app cannot hand the file over through the app group container. Each user has a separate app group container, and the extension, as root, sees a different folder from the app.

The handoff uses XPC. The extension already declares a Mach service in its Info.plist (`NEMachServiceName`). The app connects to that service and sends the downloaded bytes. The extension then applies the same rules as for its own download (`ListUpdate.evaluate`).

This fallback has a cost. It works only while a user is signed in and the app is running. If the managed-Mac test shows that the direct path works, do not build this fallback.
