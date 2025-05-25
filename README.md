![Docker Pulls](https://img.shields.io/docker/pulls/elforkhead/mamapi)

## General docker compose format:
```yaml
services:
  mamapi:
    image: elforkhead/mamapi:latest
    container_name: mamapi
    restart: unless-stopped
    volumes:
      - ./mamapi/data:/data
    environment:
      MAM_ID: yourmamapiinfohere
      TZ: Etc/UTC #https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
```
---
## ASN awareness/multisession support:
Provide the IP used to create your mam_id to enable ASN awareness. The script will only use a session that matches your current ASN to avoid session invalidations. You can provide more than one mam_id/IP combo to cover multiple ASNs, and the script will select the one that matches your current ASN.

ASN aware/multisession MAM_ID compose format:
```yaml
services:
  mamapi:
    environment:
      MAM_ID: >
        firstmamidhereoneline
        @1.1.1.1,
        secondmamidhereoneline
        @2.2.2.2,
        thirdmamidhereoneline
        @3.3.3.3
```

If you are not applying the env variable directly in the compose file (such as through a .env), you can provide it as a single string without linebreaks:
```
"firstmamidhereoneline@1.1.1.1, secondmamidhereoneline@2.2.2.2, thirdmamidhereoneline@3.3.3.3"
```
---

## Example compose entries to update Prowlarr

Add all 3 environment variables:

```yaml
services:
  mamapi:
    environment:
      UPDATE_PROWLARR: true
      PROWLARR_URL: http://192.168.0.2:9696
      PROWLARR_API: 123456789
```

---
## Example compose entries for use with gluetun:
Run behind a gluetun service in the same compose as mamapi:
```yaml
services:
  mamapi:
    network_mode: "service:gluetun"
```

Run behind a gluetun container that was not started in the same compose as mamapi:
```yaml
services:
  mamapi:
    network_mode: "container:gluetun"
```

---

## Enable debug-level logging:
```yaml
services:
  mamapi:
    environment:
      DEBUG: True
```
