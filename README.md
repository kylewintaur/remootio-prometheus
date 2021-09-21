# Go Garage

## Remootio Prometheus Exporter
A Prometheus exporter that polls a Remootio device via the API, to get the garage door open/close status.

It's written to use a Hashicorp Vault approle to get a token / get the API secret key / auth key, so you'll have to rewrite this if you're not using Vault.

You will need to edit main.go to change your Vault URL / hostname.

### Environment Variables

| Variable | Description | Default |
| -------- | ----------- | ------- |
| listenPort | Port the prometheus server will listen on | 2112 |
| remootioIP | IP:PORT of the Remootio device | x.x.x.x:8080 |
| scrapeInterval | Interval to scrape the Remootio API for an open/close status | 30 seconds |
