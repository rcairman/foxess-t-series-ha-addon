#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import struct
import time
import json
import threading
from typing import Tuple, List

# -----------------------------
# Konfiguracja
# -----------------------------

CONFIG_PATH = "/data/options.json"

with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

INVERTER_IP = config.get("inverter_ip", "192.168.1.31")
INVERTER_PORT = config.get("inverter_port", 502)

MQTT_HOST = config.get("mqtt_host", "core-mosquitto")  # w HA lepiej użyć core-mosquitto
MQTT_PORT = config.get("mqtt_port", 1883)
MQTT_USERNAME = config.get("mqtt_username", "foxess")
MQTT_PASSWORD = config.get("mqtt_password", "foxess_ha_integration")

# Prefix dla wszystkich stanów
STATE_PREFIX = "FoxESS"

# Discovery włączone/wyłączone
ENABLE_DISCOVERY = True

# Co ile próbować ponownie po rozłączeniu (sekundy)
RECONNECT_DELAY = 30

# Socket timeout (sekundy)
SOCKET_TIMEOUT = 120

# -----------------------------
# MQTT
# -----------------------------
try:
    import paho.mqtt.client as mqtt
except ImportError:
    print("Brak pakietu paho-mqtt. Zainstaluj: pip install paho-mqtt")
    raise

mqtt_client = None
availability_topic = f"{STATE_PREFIX}/availability"
device_serial = None  # uzupełnimy po ramce 0x06
device_model = None # uzupełnimy po ramce 0x01

# Mapowanie: klucz stanu -> (friendly_name, unit, device_class, state_class)
SENSOR_META = {
    "grid_power": ("Grid Power", "W", "power", "measurement"),
    "generation_power": ("Generation Power", "W", "power", "measurement"),
    "loads_power": ("Loads Power", "W", "power", "measurement"),

    "output_voltage_R": ("Output Voltage R", "V", "voltage", "measurement"),
    "output_current_R": ("Output Current R", "A", "current", "measurement"),
    "output_frequency_R": ("Output Frequency R", "Hz", None, "measurement"),
    "output_power_R": ("Output Power R", "W", "power", "measurement"),

    "output_voltage_S": ("Output Voltage S", "V", "voltage", "measurement"),
    "output_current_S": ("Output Current S", "A", "current", "measurement"),
    "output_frequency_S": ("Output Frequency S", "Hz", None, "measurement"),
    "output_power_S": ("Output Power S", "W", "power", "measurement"),

    "output_voltage_T": ("Output Voltage T", "V", "voltage", "measurement"),
    "output_current_T": ("Output Current T", "A", "current", "measurement"),
    "output_frequency_T": ("Output Frequency T", "Hz", None, "measurement"),
    "output_power_T": ("Output Power T", "W", "power", "measurement"),

    "pv1_voltage": ("PV1 Voltage", "V", "voltage", "measurement"),
    "pv1_current": ("PV1 Current", "A", "current", "measurement"),
    "pv1_power": ("PV1 Power", "W", "power", "measurement"),
    "pv2_voltage": ("PV2 Voltage", "V", "voltage", "measurement"),
    "pv2_current": ("PV2 Current", "A", "current", "measurement"),
    "pv2_power": ("PV2 Power", "W", "power", "measurement"),
    "pv3_voltage": ("PV3 Voltage", "V", "voltage", "measurement"),
    "pv3_current": ("PV3 Current", "A", "current", "measurement"),
    "pv3_power": ("PV3 Power", "W", "power", "measurement"),
    "pv4_voltage": ("PV4 Voltage", "V", "voltage", "measurement"),
    "pv4_current": ("PV4 Current", "A", "current", "measurement"),
    "pv4_power": ("PV4 Power", "W", "power", "measurement"),

    "boost_temperature": ("Boost Temperature", "°C", "temperature", "measurement"),
    "inverter_temperature": ("Inverter Temperature", "°C", "temperature", "measurement"),
    "ambient_temperature": ("Ambient Temperature", "°C", "temperature", "measurement"),

    "output_energy_today": ("Today Yield", "kWh", "energy", "measurement"),
    "output_energy_alltime": ("All-time Yield", "kWh", "energy", "total_increasing"),
}

# INFO fields (opcjonalne publikowanie)
INFO_TOPICS = [
    "Version Master",
    "Version Slave",
    "Version ARM",
    "Unknown1",
    "Model short",
    "Model full",
    "Extra",
    "Unknown2",
    "Version Master copy",
    "Version Slave copy",
    "Version ARM copy",
    "Unknown3",
    "Unknown4",
]


def mqtt_publish(topic: str, payload, retain=False, qos=0):
    """Bezpieczne publikowanie (string/float/int/list->json)."""
    if mqtt_client is None:
        return
    if isinstance(payload, (dict, list)):
        payload = json.dumps(payload, ensure_ascii=False)
    else:
        payload = str(payload)
    full_topic = topic
    try:
        mqtt_client.publish(full_topic, payload, qos=qos, retain=retain)
        # print(f"MQTT -> {full_topic}: {payload}")  # debug
    except Exception as e:
        print("MQTT publish error:", e)


def build_device_descriptor():
    identifiers = ["foxess_pvinverter"]
    if device_serial:
        identifiers.append(f"foxess_pvinverter_{device_serial}")
    return {
        "identifiers": identifiers,
        "manufacturer": "FoxESS",
        "name": "PV Inverter",
        "model": device_model or "Unknown",
    }


def publish_discovery():
    """Publikacja configów MQTT Discovery dla HA."""
    if not ENABLE_DISCOVERY or mqtt_client is None:
        return

    device = build_device_descriptor()

    for key, meta in SENSOR_META.items():
        friendly, unit, device_class, state_class = meta
        unique_id = f"foxess_{key}"
        if device_serial:
            unique_id = f"foxess_{device_serial}_{key}"

        config_topic = f"homeassistant/sensor/{unique_id}/config"
        state_topic = f"{STATE_PREFIX}/{key}"

        payload = {
            "name": f"{friendly}",
            "state_topic": state_topic,
            "unique_id": unique_id,
            "availability_topic": availability_topic,
            "device": device,
        }
        if unit:
            payload["unit_of_measurement"] = unit
        if device_class:
            payload["device_class"] = device_class
        if state_class:
            payload["state_class"] = state_class

        # specyficzne ustawienia dla output_energy_today
        if key == "output_energy_today":
            payload["suggested_display_precision"] = 1
            payload["icon"] = "mdi:solar-power"

        mqtt_publish(config_topic, payload, retain=True)

    # Faults jako osobne binary_sensor 1..8
    for i in range(8):
        key = f"fault_{i+1}"
        friendly = f"Fault Word {i+1}"
        unique_id = f"foxess_{device_serial or 'unknown'}_{key}"
        config_topic = f"homeassistant/binary_sensor/{unique_id}/config"
        state_topic = f"{STATE_PREFIX}/faults/{key}"
        payload = {
            "name": friendly,
            "state_topic": state_topic,
            "unique_id": unique_id,
            "availability_topic": availability_topic,
            "device": device,
            "device_class": "problem",
            "payload_on": "1",
            "payload_off": "0",
        }
        mqtt_publish(config_topic, payload, retain=True)

    # Info jako text sensors
    for name in INFO_TOPICS:
        key = f"info_{name}"
        unique_id = f"foxess_{device_serial or 'unknown'}_{key}"
        config_topic = f"homeassistant/sensor/{unique_id}/config"
        state_topic = f"{STATE_PREFIX}/info/{name}"
        payload = {
            "name": f"{name}",
            "state_topic": state_topic,
            "unique_id": unique_id,
            "availability_topic": availability_topic,
            "device": device,
            "icon": "mdi:information",
        }
        mqtt_publish(config_topic, payload, retain=True)


def mqtt_connect():
    global mqtt_client
    mqtt_client = mqtt.Client()
    mqtt_client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
    mqtt_client.will_set(availability_topic, "offline", retain=True)

    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            print("MQTT połączony")
            mqtt_publish(availability_topic, "online", retain=True)
        else:
            print("MQTT błąd połączenia, rc:", rc)

    mqtt_client.on_connect = on_connect
    mqtt_client.connect(MQTT_HOST, MQTT_PORT, keepalive=60)

    # uruchom loop w wątku
    thread = threading.Thread(target=mqtt_client.loop_forever, daemon=True)
    thread.start()


# -----------------------------
# Parser ramek / dekodowanie
# -----------------------------

def parse_two_bytes(b1, b2) -> int:
    return struct.unpack(">H", bytes([b1, b2]))[0]


def parse_signed_two_bytes(b1, b2) -> int:
    return struct.unpack(">h", bytes([b1, b2]))[0]


def parse_four_bytes(b1, b2, b3, b4) -> int:
    return struct.unpack(">I", bytes([b1, b2, b3, b4]))[0]


def extract_frames_from_buffer(buffer: bytes) -> Tuple[List[bytes], bytes]:
    """
    Zwraca (lista_ramek, reszta_bufora).
    Format: 0x7E 0x7E ... [len_hi len_lo] ... 0xE7 0xE7
    user_len = big-endian z pozycji [7],[8]
    total_len = user_len + 13
    """
    frames = []
    while True:
        start = buffer.find(b"\x7E\x7E")
        if start == -1:
            # Zachowaj 1 bajt jeśli kończy się na 0x7E (możliwy początek nagłówka)
            tail = buffer[-1:] if buffer.endswith(b"\x7E") else b""
            return frames, tail

        if start > 0:
            print("Nagłówek nie pasuje, przesuwam bufor")
            buffer = buffer[start:]

        if len(buffer) < 9:
            return frames, buffer

        user_len = (buffer[7] << 8) | buffer[8]
        total_len = user_len + 13

        if total_len < 15 or total_len > 4096:
            print(f"Podejrzana długość ({total_len}), odrzucam 2 bajty i resync")
            buffer = buffer[2:]
            continue

        if len(buffer) < total_len:
            return frames, buffer

        candidate = buffer[:total_len]
        if candidate[-2:] != b"\xE7\xE7":
            print("Stopka nie pasuje, odrzucam 1 bajt i resync")
            buffer = buffer[1:]
            continue

        frames.append(candidate)
        buffer = buffer[total_len:]


def decode_info(frame: bytes):
    """Ramka 0x01 – INFO (wersje, model, itp.)"""
    global device_model
    payload = frame[9:-2]
    parts = payload.split(b"\x00")
    fields = []
    for part in parts:
        if part:
            try:
                fields.append(part.decode("ascii"))
            except UnicodeDecodeError:
                fields.append(part.hex())

    labels = INFO_TOPICS

    print("Ramka INFO (0x01):")
    for i, f in enumerate(fields, 1):
        label = labels[i - 1] if i <= len(labels) else f"Field_{i}"
        print(f"  {label}: {f}")
        mqtt_publish(f"{STATE_PREFIX}/info/{label}", f, retain=False)

        # zapisz Model_full
        if label == "Model_full":
            device_model = f

def decode_data(frame: bytes):
    """Ramka 0x02 – DANE (wg offsetów z ESPHome) + MQTT publikacja."""
    if len(frame) < 160:
        print("Ramka DANYCH za krótka")
        return

    data = {}
    try:
        data["grid_power"] = parse_two_bytes(frame[9], frame[10])
        data["generation_power"] = parse_two_bytes(frame[11], frame[12])
        data["loads_power"] = parse_two_bytes(frame[13], frame[14])

        data["output_voltage_R"] = parse_two_bytes(frame[15], frame[16]) / 10
        data["output_current_R"] = parse_two_bytes(frame[17], frame[18]) / 10
        data["output_frequency_R"] = parse_two_bytes(frame[19], frame[20]) / 100
        data["output_power_R"] = parse_two_bytes(frame[21], frame[22])

        data["output_voltage_S"] = parse_two_bytes(frame[23], frame[24]) / 10
        data["output_current_S"] = parse_two_bytes(frame[25], frame[26]) / 10
        data["output_frequency_S"] = parse_two_bytes(frame[27], frame[28]) / 100
        data["output_power_S"] = parse_two_bytes(frame[29], frame[30])

        data["output_voltage_T"] = parse_two_bytes(frame[31], frame[32]) / 10
        data["output_current_T"] = parse_two_bytes(frame[33], frame[34]) / 10
        data["output_frequency_T"] = parse_two_bytes(frame[35], frame[36]) / 100
        data["output_power_T"] = parse_two_bytes(frame[37], frame[38])

        data["pv1_voltage"] = parse_two_bytes(frame[39], frame[40]) / 10
        data["pv1_current"] = parse_two_bytes(frame[41], frame[42]) / 10
#        data["pv1_power"] = parse_two_bytes(frame[43], frame[44]) / 10
        data["pv2_voltage"] = parse_two_bytes(frame[45], frame[46]) / 10
        data["pv2_current"] = parse_two_bytes(frame[47], frame[48]) / 10
#        data["pv2_power"] = parse_two_bytes(frame[49], frame[50]) / 10
        data["pv3_voltage"] = parse_two_bytes(frame[51], frame[52]) / 10
        data["pv3_current"] = parse_two_bytes(frame[53], frame[54]) / 10
#        data["pv3_power"] = parse_two_bytes(frame[55], frame[56]) / 10
        data["pv4_voltage"] = parse_two_bytes(frame[57], frame[58]) / 10
        data["pv4_current"] = parse_two_bytes(frame[59], frame[60]) / 10
#        data["pv4_power"] = parse_two_bytes(frame[61], frame[62]) / 10

        # calculate PV power manually (stream returns 0s)
        data["pv1_power"] = data["pv1_voltage"] * data["pv1_current"]
        data["pv2_power"] = data["pv2_voltage"] * data["pv2_current"]
        data["pv3_power"] = data["pv3_voltage"] * data["pv3_current"]
        data["pv4_power"] = data["pv4_voltage"] * data["pv4_current"]

        data["boost_temperature"] = parse_two_bytes(frame[63], frame[64])
        data["inverter_temperature"] = parse_two_bytes(frame[65], frame[66])
        data["ambient_temperature"] = parse_two_bytes(frame[67], frame[68])
        data["output_energy_today"] = parse_two_bytes(frame[69], frame[70]) / 10
        data["output_energy_alltime"] = parse_four_bytes(frame[71], frame[72], frame[73], frame[74]) / 10

        faults = []
        for offset in range(125, 157, 4):
            fault_val = parse_four_bytes(frame[offset], frame[offset + 1], frame[offset + 2], frame[offset + 3])
            faults.append(fault_val)
        # faults 1..8 jako osobne tematy + całość JSON
        for i, val in enumerate(faults, start=1):
            mqtt_publish(f"{STATE_PREFIX}/faults/fault_{i}", 1 if val != 0 else 0)
        mqtt_publish(f"{STATE_PREFIX}/faults/json", faults)

    except IndexError:
        print("Błąd dekodowania ramki danych (IndexError)")
        return

    print("Ramka DANYCH (0x02):")
    for k, v in data.items():
        print(f"  {k}: {v}")
        mqtt_publish(f"{STATE_PREFIX}/{k}", v)


def decode_serial(frame: bytes):
    """Ramka 0x06 – numer seryjny (obciąć 6 prefiksowych znaków i zera po numerze)."""
    global device_serial
    try:
        raw = frame[9:-2].decode("ascii", errors="ignore")
        s = raw[6:]

        import re
        match = re.search(r"0{3,}", s)
        if match:
            serial = s[:match.start()]
        else:
            serial = s.strip()

        # usuń wszystkie dziwne znaki, zostaw tylko A-Z, 0-9, - i _
        serial = re.sub(r'[^A-Za-z0-9_-]', '', serial)

    except Exception as e:
        serial = f"decode_error:{e}"

    if serial and not serial.startswith("decode_error"):
        device_serial = serial

    print("Ramka SERIAL (0x06)")
    print("  Numer seryjny:", serial)
    mqtt_publish(f"{STATE_PREFIX}/serial", serial)

    if ENABLE_DISCOVERY and device_serial:
        publish_discovery()


def decode_frame(frame: bytes):
    # walidacja długości i znaczników
    if len(frame) < 15 or not (frame.startswith(b"\x7E\x7E") and frame.endswith(b"\xE7\xE7")):
        print("Błędna ramka")
        return

    user_len = (frame[7] << 8) | frame[8]
    expected_total = user_len + 13
    if expected_total != len(frame):
        print(f"Niezgodna długość: header={expected_total}, real={len(frame)}")
        return

    function_code = frame[2]
    if function_code == 0x01:
        decode_info(frame)
    elif function_code == 0x02:
        decode_data(frame)
    elif function_code == 0x06:
        decode_serial(frame)
    else:
        print(f"Nieznany typ ramki: 0x{function_code:02X}")


# -----------------------------
# Główna pętla połączenia
# -----------------------------

def main():
    mqtt_connect()

    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(SOCKET_TIMEOUT)
            print("Łączenie z falownikiem...")
            sock.connect((INVERTER_IP, INVERTER_PORT))
            print("Połączono z falownikiem")

            buffer = b""
            while True:
                try:
                    chunk = sock.recv(2048)
                    if not chunk:
                        raise ConnectionError("Rozłączono")
                    buffer += chunk

                    frames, buffer = extract_frames_from_buffer(buffer)
                    for frame in frames:
                        decode_frame(frame)

                except (socket.timeout, ConnectionError):
                    print("Utracono połączenie z falownikiem")
                    break

        except Exception as e:
            print("Błąd połączenia:", e)

        print(f"Ponowna próba za {RECONNECT_DELAY}s...")
        time.sleep(RECONNECT_DELAY)


if __name__ == "__main__":
    main()
