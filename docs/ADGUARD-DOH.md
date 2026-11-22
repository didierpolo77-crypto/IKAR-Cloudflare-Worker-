# IKAR — AdGuard DNS-over-HTTPS endpoint

This branch adds an authenticated Vercel Function at `POST /api/dns/resolve`.

## Request

Send JSON with a DNS name and an optional record type:

```http
POST /api/dns/resolve
Authorization: Bearer <IKAR_API_TOKEN>
Content-Type: application/json

{"name":"example.com","type":"A"}
```

Allowed record types: A, AAAA, CNAME, MX, NS, TXT. The function forwards the DNS question to AdGuard Public DNS JSON DoH at `https://dns.adguard-dns.com/resolve` and returns the DNS status and answer records.

## Important scope limitation

This endpoint performs explicit DNS lookups through AdGuard DoH. It does **not** transparently change the operating-system resolver used by Node.js or force every outbound HTTPS connection from Vercel through AdGuard. Existing `fetch()` calls (for example to Hugging Face or URLhaus) still use the Vercel runtime's normal network resolution. Do not describe this as full-server DNS routing or a proxy.

To route every server-side hostname lookup through a chosen resolver, the hosting runtime must support configuring its resolver/network stack or an outbound proxy/gateway. A normal Vercel Function does not expose a general-purpose DNS server port or transparent network gateway.
