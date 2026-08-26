FROM python:3.12-slim

# Pinned to match your manager exactly (4.14.5)
ARG WAZUH_VERSION=4.14.5-1
ARG WAZUH_MANAGER=host.docker.internal
ARG WAZUH_AGENT_NAME=iomt-vitals-monitor

# System deps + the Wazuh agent (same .deb your dashboard generated)
RUN apt-get update && apt-get install -y --no-install-recommends \
        wget ca-certificates procps lsb-release iptables iproute2 \
    && wget -q "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_${WAZUH_VERSION}_amd64.deb" -O /tmp/wazuh-agent.deb \
    && (WAZUH_MANAGER="${WAZUH_MANAGER}" WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME}" dpkg -i /tmp/wazuh-agent.deb || apt-get install -f -y) \
    && rm -f /tmp/wazuh-agent.deb \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Our explicit agent config (manager address + FIM on the "patient records" dir)
COPY ossec.conf /var/ossec/etc/ossec.conf
RUN chown root:wazuh /var/ossec/etc/ossec.conf && chmod 640 /var/ossec/etc/ossec.conf

# A "patient records" directory -- the target the ransomware scenario (Workstream B) will encrypt.
RUN mkdir -p /medical-data \
    && printf 'patient,hr,spo2\nA001,78,97\n' > /medical-data/record-001.csv \
    && printf 'patient,hr,spo2\nA002,82,96\n' > /medical-data/record-002.csv

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY publisher.py hl7_sender.py entrypoint.sh ./
RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
