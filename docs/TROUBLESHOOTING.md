# Troubleshooting

- **Browser warns about the certificate at https://localhost:8443**
  The dev certificate is self-signed. Accept the warning for local use.
- **`make` is not available on Windows**
  Open the Makefile and run the underlying commands by hand.
- **Requests rejected with 401 even though login works**
  Check that the client and server clocks agree within about 60 seconds.
  DPoP uses a 60 s timestamp window.
- **Need a clean start**
  Run `make down` to wipe volumes, then `make up` to rebuild and re-seed.
- **Dev credentials**
  Seed logins are in seed/generated/credentials.json. They are dev-only and
  must never be committed.
