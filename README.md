# FoxESS T-Series PV inverter MQTT integration with Home Assistant

An add-on for Home Assistant that integrates FoxESS T-series inverter via MQTT.
Data is read directly from the inverter (RS485 to TCP adapter) and published to the MQTT broker
(e.g., *core-mosquitto* in Home Assistant).

## Features
- automatic MQTT Discovery in Home Assistant
- measurements of power, voltages, currents, and temperatures
- daily and total energy production
- fault (error) reporting

## Installation
1. In Home Assistant go to **Settings → Add-ons → Add-on Store → Repositories**
   and add the URL of this repository.
2. Select **FoxESS T-Series PV inverter MQTT integration with Home Assistant** from the list and click *Install*.
3. Configure the parameters (MQTT connection, inverter IP address).
4. Start the add-on.