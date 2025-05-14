# NGU NADAG Maskinporten eksempel klient v.1.0.0

Enkel test klient for NADAG API som tester autentisering og leveranse av en enkel grunnundersøkelse med vedlegg.

Konfigurering før bruk (example-client.properties):

1. Organisasjonens sertifikat (certificate) mot maskinporten må inkluderes i prosjektet og refereres i konfigurasjonsfil (PEM-fil benyttes).
2. Organisasjonens private nøkkel (private_key) mot maskinporten må inkluderes i prosjektet og refereres i konfigurasjonsfil (DER-fil benyttes).
3. Organisasjonens offentlige nøkkel id (kid) hos maskinporten må konfigurerers.
4. Organisasjonsnummer (consumer_org) for organisasjonen må konfigurerers.
5. Brukerens id i NADAG (user_uuid) må konfigurerers. 

Referanser:

https://github.com/felleslosninger/jwt-grant-generator
https://docs.digdir.no/docs/Maskinporten
https://docs.altinn.studio/nb/notifications/guides/maskinporten-client/