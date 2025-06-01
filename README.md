![Docker Pulls](https://img.shields.io/docker/pulls/elforkhead/mamapi)

## General docker compose format
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
Also available from GHCR:
```yaml
    image: ghcr.io/elforkhead/mamapi:latest
```
---
## ASN awareness/multisession support
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
## Compose networking examples with gluetun
Run behind a gluetun service in the same compose as mamapi

```yaml
services:
  mamapi:
    network_mode: "service:gluetun"
```

Or run behind a gluetun container that was not started in the same compose as mamapi

```yaml
    network_mode: "container:gluetun"
```

---

## Optional/advanced environment variables

Debug-level logging. Not recommended for general use.

```yaml
DEBUG: True
```

Write the mam_id in use to a "current_mamid" file in the data directory

```yaml
WRITE_CURRENT_MAMID: True
```