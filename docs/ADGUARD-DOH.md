# IKAR — AdGuard DNS-over-HTTPS

## Endpoint

`POST /api/dns/resolve`

Requires the existing `IKAR_API_TOKEN` environment variable:

`Authorization: Bearer <IKAR_API_TOKEN>`

JSON body:

```json
{ "name": "example.com", "type": "A" }
```

Supported record types: A, AAAA, CNAME, MX, NS, TXT. If omitted, type defaults to A.

The function sends this explicit DNS lookup to AdGuard Public DNS over HTTPS at
`https://dns.adguard-dns.com/resolve` and returns the DNS status and up to 20 answers.

## Important limitation

This endpoint routes only DNS lookups made through this endpoint to AdGuard. It does
not force every outbound connection or the platform's general Node.js resolver to use
AdGuard. It is not a network-wide DNS gateway.
