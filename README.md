# elforkhead's mamapi container

![Docker Pulls](https://img.shields.io/docker/pulls/elforkhead/mamapi)

**If you're using a VPN, choose a single city/region as your endpoint.** Different regions will be in a different ASN, and MAM requires a unique session for each ASN.

## ASN awareness/multisession support
Provide the IP used to create your mam_id to enable ASN awareness. The script will only use a session that matches your current ASN to avoid session invalidations. You can provide more than one mam_id/IP combo to cover multiple ASNs, and the script will select the one that matches your current ASN. You can provide a single mam_id without an IP to disable all ASN-aware features.

## Docker compose:
```yaml
services:
  mamapi:
    image: elforkhead/mamapi:latest
    # also available at ghcr.io/elforkhead/mamapi:latest
    volumes:
      - ./mamapi/data:/data
    environment:

      TZ: America/New_York #https://en.wikipedia.org/wiki/List_of_tz_database_time_zones

      # mam_id@ip.used.to.create
      MAM_ID: >
        firstmamidhereoneline
        @1.1.1.1,
        secondmamidhereoneline
        @2.2.2.2,
        thirdmamidhereoneline
        @3.3.3.3

      # OR ONE LINE FORMAT, USEFUL IF YOUR ARE NOT WRITING DIRECTLY IN YAML
      # MAM_ID: "firstmamidhereoneline@1.1.1.1, secondmamidhereoneline@2.2.2.2, thirdmamidhereoneline@3.3.3.3"
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

**Debug-level logging.**

Not recommended for general use.

```yaml
DEBUG: True
```

---

**Write the mam_id in use to a "current_mamid" file in the data directory.**

```yaml
WRITE_CURRENT_MAMID: True
```

---

**Exit the container when its internet connection is lost.**

Use in conjunction with a docker restart policy of 'unless-stopped' to force a container restart if network connection is lost. Useful if you lose connection when your VPN container restarts.

```yaml
SHUTDOWN_ON_DISCONNECT: True
```

---

**Error notifications through apprise.**

[Provide a comma separated list of apprise service URLs](https://github.com/caronc/apprise). Notifications will be sent only in error states that occur after initial setup (no notifications for problems you'd find on your first run). This includes things like session invalidations and lacking an appropriate mam_id for the current session.

```yaml
services:
  mamapi:
    environment:
      NOTIFY_URLS: >
        firsturlhere,
        secondurlhere,
        thirdurlhere
      # OR ONE LINE FORMAT, USEFUL IF YOUR ARE NOT WRITING DIRECTLY IN YAML
      NOTIFY_URLS: "firsturlhere, secondurlhere, thirdurlhere"
```
