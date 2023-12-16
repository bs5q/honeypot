# Honeypot System 🍯🛡️

Honeypot detects potential threats, alerts, and reports to a Telegram bot, im adding AbuseIPDB reports soon.

## Features

- Simulates handling connections and logs potential attack patterns.
- Sends alerts to Telegram on potential threats.
- Reports malicious IPs to AbuseIPDB. `SOON`

## Prerequisites

- Go installed on your machine.
- A valid Telegram bot token for receiving alerts.
- (Optional) An AbuseIPDB API key for reporting malicious IPs. `SOON`

## Configuration

1. Edit the `config.json` file based i provided.
2. Replace placeholder values with your Telegram bot token.

## How to Run

1. Open a terminal window.
2. Navigate to the project directory.
3. Run the following commands:

   ```bash
   go build
   ./honeypot
