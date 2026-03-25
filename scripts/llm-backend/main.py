import os
import json
import paho.mqtt.client as mqtt
import requests
# Template w kahaw ma aandou hata maana taw
# Configuration
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama-server:11434/api/generate")
MQTT_BROKER = os.getenv("MQTT_BROKER", "honey-mqtt")
MQTT_TOPIC = "honey/threat_intel"

# Initialize MQTT
client = mqtt.Client()

def on_connect(client, userdata, flags, rc):
    print(f"Connected to MQTT Broker with result code {rc}")
    client.subscribe(MQTT_TOPIC)

def get_llm_response(prompt, context=""):
    """
    Sends a prompt to the local Ollama instance.
    """
    payload = {
        "model": "llama3",
        "prompt": f"Context: {context}\n\nUser Input: {prompt}",
        "stream": False
    }
    try:
        response = requests.post(OLLAMA_URL, json=payload)
        return response.json().get("response", "Internal Server Error")
    except Exception as e:
        return f"Error connecting to AI Brain: {str(e)}"

# Core logic for analyzing attacker intent
def analyze_intent(data):
    # This will be used to update the Grafana dashboard via MQTT/InfluxDB
    pass

if __name__ == "__main__":
    client.on_connect = on_connect
    client.connect(MQTT_BROKER, 1883, 60)
    client.loop_forever()

