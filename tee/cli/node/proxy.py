"""Legacy cvm-reverse-proxy attestation client — RETIRED, not wired up.

This shells Flashbots' Go `cvm-reverse-proxy` `proxy-client` to verify a
node's TDX attestation over an RA-TLS channel on `:7936`. It is currently
non-functional and kept only as a reference skeleton:

  - No node serves `:7936` — seismic nodes terminate public TLS with
    nginx+certbot, and RA-TLS is still a TODO in seismic-images.
  - Wrong protocol: cvm-reverse-proxy embeds the quote in a *self-signed*
    cert (pre-handshake aTLS), whereas the enclave standardizes on
    `flashbots/attested-tls`, whose attested channel runs under an outer
    CA-signed cert. Only the measurements.json format is shared.

Verification will be reimplemented against attested-tls /
seismic-attestation (the enclave already exposes `getAttestationEvidence`
plus a deploy-preflight binding for exactly this). Until then the caller
(`configure`) refuses `--measurements` rather than pretending to verify.
"""

import json
import logging
import subprocess
import threading
import time
from pathlib import Path

import requests

logger = logging.getLogger(__name__)


class ProxyClient:
    def __init__(self, public_ip: str, measurements_file: Path, home: str):
        self.public_ip = public_ip
        self.measurements_file = measurements_file
        self.executable_path = Path(home) / "cvm-reverse-proxy/build/proxy-client"
        self.process: subprocess.Popen | None = None

    def start(self) -> bool:
        """Start the proxy client, make an HTTP request, verify.

        Verifies attestation.
        """

        proxy_cmd = [
            self.executable_path,
            "--target-addr",
            f"https://{self.public_ip}:7936",
            "--server-attestation-type",
            "azure-tdx",
            "--server-measurements",
            str(self.measurements_file),
        ]

        # Start the proxy client process
        try:
            self.process = subprocess.Popen(
                proxy_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            logger.info(f"Starting proxy client to https://{self.public_ip}:7936")

            # Wait for the process to confirm startup or timeout after 5 seconds
            try:
                self.process.wait(timeout=5)
                if self.process.returncode is not None:
                    if self.process.stderr is None:
                        raise RuntimeError(f"{proxy_cmd} failed with no stderr")
                    stderr_output = self.process.stderr.read().decode()
                    raise RuntimeError(
                        f"Proxy process terminated immediately: {stderr_output}"
                    )
            except subprocess.TimeoutExpired:
                logger.info("Proxy client has started successfully")

            # Start a thread to perform the HTTP request after a short delay
            request_thread = threading.Thread(target=self.perform_http_request)
            request_thread.start()

            # Monitor proxy output for successful attestation message
            return self._monitor_attestation(request_thread)

        except FileNotFoundError as e:
            logger.error("Proxy client binary not found at specified path.")
            raise FileNotFoundError("Proxy client binary not found.") from e
        except RuntimeError as e:
            logger.error(f"Failed to start proxy: {e}")
            raise
        finally:
            self.stop()

    def _monitor_attestation(self, request_thread: threading.Thread) -> bool:
        """Monitor proxy output for successful attestation validation."""
        start_time = time.time()
        while True:
            # Read output line by line from stdout
            if self.process and self.process.stdout:
                output = self.process.stdout.readline().decode().strip()
                if output:
                    logger.info(f"Proxy stdout: {output}")

                # Look for attestation validation message
                if "Successfully validated attestation document" in output:
                    logger.info("Proxy server validated attestation successfully")
                    # Ensure HTTP request thread has completed
                    request_thread.join()
                    return True

                # Timeout after 30 seconds if no validation message is found
                if time.time() - start_time > 30:
                    logger.error("Timeout: Attestation validation message not found")
                    self.stop()
                    raise TimeoutError(
                        "Timeout: Attestation validation message not found."
                    )

            time.sleep(1)  # Slight delay to avoid CPU overuse

    def perform_http_request(self):
        """Simulate an external HTTP request to the proxy server"""
        # Wait to ensure proxy client is running
        # before sending the request
        time.sleep(5)
        try:
            response = requests.get(
                "http://localhost:8080/genesis/data",
                headers={"Host": "localhost"},
            )
            response.raise_for_status()
            output = json.dumps(response.json())
            logger.info(f"HTTP request succeeded with output:\n{output}")
        except requests.RequestException as e:
            logger.error(f"HTTP request failed: {e}")
            raise ConnectionError(f"HTTP request to proxy server failed: {e}") from e

    def stop(self):
        """Stop the proxy client"""
        if self.process:
            self.process.terminate()
            logger.info("Proxy client stopped")
            self.process = None
