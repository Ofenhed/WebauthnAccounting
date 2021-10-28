# Accountability in federated login systems
I recently though about the difficulties in secure a database and its data when using federated login when you don't fully trust the identity provider (hereby referred to as IdP). This is a common use case these days, where IdP:s are moved to cloud systems, such as Azure AD. This adds additional threats, both from [state actors with legal rights to force the IdP provider to give them access](https://kryptera.se/molntjanster-och-fisa-702/), but also from [vulnerabilities in the IdP itself](https://www.cvedetails.com/vulnerability-list/vendor_id-26/product_id-38600/Microsoft-Azure-Active-Directory-Connect.html). For this reason, I want a another authentication (and authorization) factor for any such systems.

## Skip federated login
It could be argued that this threat can be mitigated by not using federated logins. Please don't.
TODO: Further argue why you should not implement user authentication

## Webauthn
Webauthn is an API for accessing devices which can help authencicate a user. It uses public keys, where the hardware keys can be stored on hardware devices. It initially sets up the key by asking the device to generate a public/private keypair. The device responds with a public key and an identifier (where the identifier *may* include the encrypted private key). The server can then provide the identifier and a challenge to the device to get a response verifiable against the previously provided public key.

## General suggestion
The federated login system is likely correct (as the threats on most days are likely small), so we should mostly trust it.
* **Login**: We hold a database table with Webauthn data for each persistent identifier of a user received from the IdP. Users authenticated by the IdP who doesn't hold a valid entry in the webauthn data table should not be able to log in. After a successful federated login, the user should be forced to authenticate using Webauthn.
* **Administration of Webauthn data**: Only users marked by the IdP (or hard coded in a configuration file, depending on how much the IdP is trusted) must be able to add or remove Webauthn data for other users.
* **Multiple keys allowed**: All users should be able to add or remove Webauthn data for themselves.
* **Tracability**: Webauthn data can never be removed, only marked as revoked.
* **Accountability**: All (privileged) actions are signed by the Webauthn token. See [signed actions](#signed-actions).

## Technical implementation
### Signed actions
In this case, we have a logged in user who wants to add a row in a table. The user gets the following form (with labels and layout skipped for simplicity):

```html
<form method="post">
  <input type="text" name="customer" />
  <input type="text" name="service" />
  <input type="date" name="paid-through" />
  <input type="hidden" name="csrf-token" value="unpredictable value also stored in cookie" />
  <input type="hidden" name="challenge" value="unpredictable value which has not previously been used in the database" />
  <input type="hidden" name="response" />
  <button onclick="sign_and_submit()">
    Submit
  </button>
</form>
```

The `sign_and_submit()` function should do the following:
1. Generate a bytestring from the form fields (excluding the `csrf-token`). A good solution would be JSON encoded dictionary sorted by key name.
2. Generate a hash (TODO: Which length? How big challenges does Webauthn support?)

## TODO: Case 1 - We are a service provider
### Assumptions
* Our system contains no sensitive data
* Our system can be used to gain access to customer networks
* Customer networks contain sensitive data

### Suggestion
TODO

## Rationale
