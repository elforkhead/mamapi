# elforkhead's mamapi container

![Docker Pulls](https://img.shields.io/docker/pulls/elforkhead/mamapi)

**If you're using a VPN, choose a single city/region as your endpoint.** Different regions will be in a different ASN, and MAM requires a unique session for each ASN.

**UPDATE:** multisession support has been discontinued with the introduction of MAM's new ASN features. Please pass only one mam_id as your MAM_ID environment variable. **Do not include the IP used to create the session** (the old @1.1.1.1 format).

Additional ASNs can be added to your session in the MAM 'Security' tab.

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
      MAM_ID: mamidhere123456
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

[Provide a comma separated list of apprise service URLs](https://github.com/caronc/apprise). Sends a notification if your current ASN has not been authorized with MAM.

```yaml
NOTIFY_URLS: >
  firsturlhere,
  secondurlhere,
  thirdurlhere
# OR ONE LINE FORMAT, USEFUL IF YOUR ARE NOT WRITING DIRECTLY IN YAML
NOTIFY_URLS: "firsturlhere, secondurlhere, thirdurlhere"
```