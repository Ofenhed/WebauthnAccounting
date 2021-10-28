# Accountability in federated login systems
I recently though about the difficulties in secure a database and its data when using federated login when you don't fully trust the identity provider (hereby referred to as IdP). This is a common use case these days, where IdP:s are moved to cloud systems, such as Azure AD. This adds additional threats, both from [state actors with legal rights to force the IdP provider to give them access](https://kryptera.se/molntjanster-och-fisa-702/), but also from [vulnerabilities in the IdP itself](https://www.cvedetails.com/vulnerability-list/vendor_id-26/product_id-38600/Microsoft-Azure-Active-Directory-Connect.html). For this reason, I want a another authentication (and authorization) factor for any such systems. **This document is not an argument against federated login.** Users reuse passwords, and LDAP logins still makes it so that passwords are leaked into unallocated memory or can be sniffed by malware on the server. You should not create your own login system if you don't really have to, and you should treat user's passwords as if they are infected.

## Webauthn
Webauthn is an API for accessing devices which can help authencicate a user. It uses public keys, where the hardware keys can be stored on hardware devices. It initially sets up the key by asking the device to generate a public/private keypair. The device responds with a public key and an identifier (where the identifier *may* include the encrypted private key). The server can then provide the identifier and a challenge to the device to get a response verifiable against the previously provided public key.

## General suggestion
The federated login system is likely correct (as the threats on most days are likely small), so we should mostly trust it.
* **Login**: We hold a database table with Webauthn data for each persistent identifier of a user received from the IdP. Users authenticated by the IdP who doesn't hold a valid entry in the webauthn data table should not be able to log in. After a successful federated login, the user must be forced to authenticate using Webauthn. If there is no `WEBAUTHN_TOKEN` for the current user, then the users in `TOKEN_ADMINISTRATOR` should be notified and the user must be denied access.
* **Administration of Webauthn data**: Only users marked by the IdP (or hard coded in a configuration file, depending on how much the IdP is trusted) must be able to add or remove Webauthn data for other users.
* **Multiple keys allowed**: All users should be able to add or remove Webauthn data for themselves.
* **Tracability**: Webauthn data can never be removed, only marked as revoked.
* **Accountability**: All (privileged) actions are signed by the Webauthn token. See [signed actions](#signed-actions).

## Technical implementation
### Database tables
Rows similar to the meta-sql below should be in our local database. The Webauthn data must not be fetched from the IdP, as this gives back the extra trust we tried to deny the IdP.

#### CHALLENGE
| CHALLENGE   | GENERATED_AT                       | USED                   |
| ----------- | ---------------------------------- | ---------------------- |
| PRIMARY KEY | NOT NULL DEFAULT CURRENT_TIMESTAMP | NOT NULL DEFAULT FALSE |

Unused challenges may (but should not) be deleted after a certain time, used challenges may not. All tables which has a challenge should refer to this table.

#### ROW_SIGNATURE
| ID          | CHALLENGE_SEED                           | SIGN_KEY_ID                                | SERIALIZATION_VERSION | RESPONSE |
| ----------- | ---------------------------------------- | ------------------------------------------ | --------------------- | -------- |
| PRIMARY KEY | NOT NULL REFERENCES(CHALLENGE.CHALLENGE) | NOT NULL REFERENCES(WEBAUTHN_TOKEN.KEY_ID) | NOT NULL              | NOT NULL |

#### TOKEN_ADMINISTRATOR
| USER        | SIGNATURE                             |
| ----------- | ------------------------------------- |
| PRIMARY KEY | NOT NULL REFERENCES(ROW_SIGNATURE.ID) |

#### WEBAUTHN_TOKEN
| KEY_ID      | PUB_KEY  | USER     | SIGNATURE                             |
| ----------- | -------- | -------- | ------------------------------------- |
| PRIMARY KEY | NOT NULL | NOT NULL | NOT NULL REFERENCES(ROW_SIGNATURE.ID) |

The database should be set up in such a way that a self signed (where `SIGNATURE.SIGN_KEY_ID` equals `KEY_ID`) row cannot be added by the database user, so that it can only be setup during first installation.

### Signed actions
All security critical actions in the database must be verifiable to a user. For this reason, Webauthn data must be immutable and bound to a user. Removal of Webauthn data must be performed as a flag on the row, and not by actually removing it. If this is not fulfilled, then the data can only be traced to a specific `key-id`, but that's not very useful if it cannot be traced to an actual user.

#### Adding a row to the database
In this case, we have a logged in user who wants to add a row in a table. The user gets the following form (with labels and layout skipped for simplicity):

```html
<form method="post">
  <input type="text" name="customer" />
  <input type="text" name="service" />
  <input type="date" name="paid-through" />
  <input type="hidden" name="csrf-token" value="unpredictable value also stored in cookie" />
  <input type="hidden" name="serialization-version" value="The version of the table. Used to be able to verify older rows after database structure changes." />
  <input type="hidden" name="challenge-seed" value="unpredictable and unique value which has not previously been used in the database" />
  <input type="hidden" name="response" />
  <input type="hidden" name="key-id" />
  <button onclick="sign_and_submit()">
    Submit
  </button>
</form>
```

The `sign_and_submit()` function should do the following:
1. Generate a predictable bytestring `Bf` from the form fields (excluding `csrf-token`, `response` and `key-id`). A good solution would be JSON encoded dictionary sorted by key name.
2. Generate a 32 byte hash `Hf` from the bytestring `Bf`.
3. Perform an authentication against all known Webauthn keys for the current user, using the challenge `Hf`.
4. Save the Webauthn key id and response to the fields `response` and `key-id`.
5. Submit the form.

The server should then perform the following:
1. Verify that the `challenge-seed` is the same challenge as was sent to the user. This could be saved in cookies, or the server could have it saved in a cookie, or it could just verify that it is a challenge which the server has (recently) generated but not gotten a response to.
2. Generate a predictable bytestring `Bs` in the same way as `Bf` was generated above.
3. Generate a 32 byte hash `Hs` from the bytestring `Bs`.
4. Fetch the public key matching `key-id` from the database, and verify `response` against the challenge `Hs`.
5. Store everyting except `csrf-token` in the database, to allow for future verification.

#### Modifying a row in the database
Modified rows must replace not only the data it modifies, but also the signature of the user modifiying it. The database should save old rows (and signatures) to be able to track who introduced a change.

#### Deleting a row in the database
This introduces a very interesting challenge. How do we delete a row in such a way that it can no longer be used?

##### Simply delete it
If we simply delete rows in the database, then they can still be reinserted if the raw data can be found somewhere else. It also requires that logging is separate for who deleted the post. This removes accountability for the deleted data, though.

##### Mark it
To delete the row by marking it the table would have additional fields for deletion in the same way as creation, with a unique `delete-challenge`, `delete-response` and `delete-key-id`. This means that a row with `delete-response` not being `null` can be assumed to be deleted. This would likely require privileged triggers in the database to be enforced though, since the `delete-challenge`, `delete-key-id` and `delete-response` mustn't be nullable after having been set. This still maintains accountability for both creation and deletion of data, even after the deletion.

#### Verification
A reviewer can, at any time, fetch all data from a database for verification. A problem here is that all previous ways of generating a predictable hash from the data of each table must be saved and the correct algorithm is chosen by looking at the `SERIALIZATION_VERSION` for the row. This check should be automated, both on a schedule and when reading security critical rows from the database.

## Result
If this is implemented, all administrative actions should require a Multi-Factor authentication device to be performed, while authorization can still be controlled centrally, for example in the AD. All actions can also be verified to have originated from a specific user, or to be invalid. New users will have to be added in a local administrative interface, though, since it's not enough to add a user in the IdP.
