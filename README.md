# FoxESS T-Series PV inverter MQTT integration with Home Assistant

An add-on for Home Assistant that integrates FoxESS T-series inverter via MQTT.
Data is read directly from the inverter (RS485 to TCP adapter) and published to the MQTT broker
(e.g., *core-mosquitto* in Home Assistant).

FoxESS T-series do not support Modbus. A simple, binary protocol is used on RS-485 interface. Data is updated approx. every 90sec. This is much better than via the cloud, but still far from what Modbus-capable inverters can offer.

This project is not maintained, I made it for my own use. You are welcome to use and modify it at your own risk.

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

## Credits
FoxESS protocol mapping has been borrowed from https://github.com/assembly12/Foxess-T-series-ESPHome-Home-Assistant