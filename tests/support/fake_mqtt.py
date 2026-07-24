# tests/support/fake_mqtt.py
"""In-memory MQTT client double: records publishes/subscriptions, no broker."""


class FakeMqttClient:
    def __init__(self):
        self.published = []       # list of (topic, payload, retain)
        self.subscriptions = []
        self.lwt = None
        self.connected = False
        self.loop_running = False
        self.on_message = None

    def will_set(self, topic, payload=None, retain=False, qos=0):
        self.lwt = (topic, payload, retain)

    def username_pw_set(self, username, password=None):
        self.auth = (username, password)

    def connect(self, host, port=1883, keepalive=60):
        self.connected = True

    def subscribe(self, topic, qos=0):
        self.subscriptions.append(topic)

    def publish(self, topic, payload=None, qos=0, retain=False):
        self.published.append((topic, payload, retain))

    def loop_start(self):
        self.loop_running = True

    def loop_stop(self):
        self.loop_running = False

    def disconnect(self):
        self.connected = False

    def find(self, topic):
        """Latest payload published to `topic`, or None."""
        for t, p, _ in reversed(self.published):
            if t == topic:
                return p
        return None
