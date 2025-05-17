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
## ASN awareness:
You can provide the IP used to create a particular session/mam_id to enable ASN awareness. The IP will be used to find the ASN expected by that particular session. The script will determine the ASN of your connection, and will select the appropriate mam_id to use. If no mam_id has an ASN matching your current IP, the script will hang to avoid invalidating any sessions, and provide feedback to help you create another session.

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

If you are not applying the env variable directly in the compose file (such as through a .env), you will need to provide it as a single string without linebreaks:
```
"firstmamidhereoneline@1.1.1.1, secondmamidhereoneline@2.2.2.2, thirdmamidhereoneline@3.3.3.3"
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
