"""
Shared API client with auto-detection (Anthropic / OpenAI) and curl fallback.

Eliminates duplicated API calling logic across scripts.
"""

import json
import subprocess
import time

import httpx

from api_relay_audit.stream_integrity import StreamSignals


def _parse_curl_i_output(output: str) -> dict:
    """Parse ``curl -i`` (or ``curl -sk -i``) stdout into a response dict.

    Handles HTTP/1.x and HTTP/2 status lines and normalises ``\\r\\n`` line
    endings. A leading ``HTTP/X 100 Continue`` preface is skipped so the
    final status is surfaced.

    Returns ``{"status": int, "headers": dict, "body": str, "error": str|None}``
    where ``status == 0`` indicates a parse failure (``error`` set to a
    short diagnostic string).
    """
    if not output:
        return {"status": 0, "headers": {}, "body": "", "error": "empty curl output"}

    # Normalise line endings so the \n\n separator is reliable.
    text = output.replace("\r\n", "\n")

    # Split into header block / body on the first blank line.
    sep_idx = text.find("\n\n")
    if sep_idx == -1:
        return {"status": 0, "headers": {}, "body": text, "error": "no header/body separator"}
    headers_block = text[:sep_idx]
    body_block = text[sep_idx + 2:]

    # Skip any ``HTTP/X 100 Continue`` preface followed by its own blank line.
    while headers_block.split("\n", 1)[0].find(" 100 ") != -1:
        next_sep = body_block.find("\n\n")
        if next_sep == -1:
            return {"status": 0, "headers": {}, "body": body_block,
                    "error": "unterminated 100 Continue preface"}
        headers_block = body_block[:next_sep]
        body_block = body_block[next_sep + 2:]

    lines = headers_block.split("\n")
    status_line = lines[0] if lines else ""
    # "HTTP/1.1 404 Not Found" or "HTTP/2 404"
    parts = status_line.split(" ", 2)
    status = 0
    if len(parts) >= 2:
        try:
            status = int(parts[1])
        except ValueError:
            status = 0

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()

    return {
        "status": status,
        "headers": headers,
        "body": body_block,
        "error": None,
    }


def _populate_stream_signals(event: dict, signals: StreamSignals) -> None:
    """Dispatch a single parsed SSE event dict into a StreamSignals.

    Mutates ``signals`` in place. Never raises — malformed fields
    are silently ignored so a broken event anywhere in the stream
    does not abort the rest of the parse.

    This helper lives at module scope (rather than on ``APIClient``)
    so it can be unit-tested without instantiating a client or
    touching the network.
    """
    signals.raw_event_count += 1
    event_type = event.get("type", "")
    if isinstance(event_type, str) and event_type:
        signals.event_types.append(event_type)

    if event_type == "message_start":
        signals.has_message_start = True
        message = event.get("message", {})
        if isinstance(message, dict):
            model_name = message.get("model")
            if isinstance(model_name, str):
                signals.message_start_model = model_name
            usage = message.get("usage", {})
            if isinstance(usage, dict):
                input_tokens = usage.get("input_tokens")
                if isinstance(input_tokens, int):
                    signals.input_tokens = input_tokens

    elif event_type == "content_block_start":
        signals.has_content_block_start = True
        block = event.get("content_block", {})
        if isinstance(block, dict):
            block_type = block.get("type", "")
            if isinstance(block_type, str) and block_type:
                signals.content_block_types.append(block_type)
            if block.get("type") == "thinking":
                signals.thinking_start_seen = True

    elif event_type == "content_block_delta":
        signals.has_content_block_delta = True
        delta = event.get("delta", {})
        if isinstance(delta, dict):
            delta_type = delta.get("type")
            if isinstance(delta_type, str) and delta_type:
                signals.delta_types.append(delta_type)

            if delta_type == "text_delta":
                signals.has_text_delta = True
            elif delta_type == "thinking_delta":
                signals.thinking_delta_seen = True
            elif delta_type == "signature_delta":
                signature = delta.get("signature")
                if isinstance(signature, str) and not signature.strip():
                    signals.empty_signature_delta_count += 1

    elif event_type == "message_delta":
        signals.has_message_delta = True
        usage = event.get("usage", {})
        if isinstance(usage, dict):
            input_tokens = usage.get("input_tokens")
            if isinstance(input_tokens, int):
                signals.message_delta_input_tokens_samples.append(input_tokens)
            output_tokens = usage.get("output_tokens")
            if isinstance(output_tokens, int):
                signals.output_tokens_samples.append(output_tokens)

    elif event_type == "message_stop":
        signals.has_message_stop = True


def _parse_sse_stream(byte_iterator, signals: StreamSignals) -> None:
    """Consume a byte iterator and populate ``signals`` with every
    SSE event it contains.

    Handles:

    - Multi-byte chunks that split in the middle of a UTF-8 sequence
      (uses ``errors="ignore"`` on decode so we don't wedge)
    - Multiple events in a single chunk
    - A single event split across multiple chunks (buffered until
      a newline is seen)
    - A terminal ``data: [DONE]`` sentinel
    - Malformed JSON lines (skipped silently, do not abort the
      rest of the stream)
    - Empty lines / non-``data: `` lines (skipped)

    Never raises. Mutates ``signals`` in place.
    """
    buffer = ""
    for chunk in byte_iterator:
        if isinstance(chunk, (bytes, bytearray)):
            buffer += chunk.decode("utf-8", errors="ignore")
        else:
            buffer += chunk
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            line = line.strip()
            if not line.startswith("data: "):
                continue
            data = line[6:]
            if data == "[DONE]":
                return
            try:
                event = json.loads(data)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                _populate_stream_signals(event, signals)


class APIClient:
    """Unified API client that auto-detects Anthropic vs OpenAI format.

    On the first ``call()``, the client tries the Anthropic native message
    format and, if that fails, falls back to the OpenAI-compatible
    ``/chat/completions`` endpoint.  If a Python-level SSL error is
    encountered, the transport silently switches to a ``curl -sk``
    subprocess so the audit can continue against self-signed relays.

    Attributes:
        base_url: Root URL of the relay (trailing slash stripped).
        api_key: Bearer / x-api-key token.
        model: Model identifier forwarded to the relay.
        timeout: Per-request timeout in seconds.
        verbose: If ``True``, diagnostic messages are printed to stdout.
    """

    def __init__(self, base_url: str, api_key: str, model: str,
                 timeout: int = 120, verbose: bool = True):
        """Initialise the client.

        Args:
            base_url: Root URL of the API relay (e.g. ``"https://relay.example.com"``).
            api_key: Authentication token sent as ``x-api-key`` (Anthropic)
                or ``Authorization: Bearer`` (OpenAI).
            model: Model identifier to include in every request body.
            timeout: HTTP / curl timeout in seconds. Defaults to 120.
            verbose: Whether to print diagnostic log lines. Defaults to True.
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.verbose = verbose
        self._format = None   # "anthropic" | "openai" | None (auto)
        self._use_curl = False

    @property
    def detected_format(self):
        """Return the detected API format.

        Returns:
            The string ``"anthropic"``, ``"openai"``, or ``None`` if
            auto-detection has not yet been performed.
        """
        return self._format

    def _log(self, msg: str):
        if self.verbose:
            print(msg)

    # -- Low-level transport --------------------------------------------------

    def _curl_post(self, url: str, headers: dict, body: dict) -> dict:
        cmd = ["curl", "-sk", "-X", "POST", url, "--max-time", str(self.timeout),
               "--config", "-"]
        cmd.extend(["-d", json.dumps(body)])
        config = "\n".join(f'header = "{k}: {v}"' for k, v in headers.items())
        r = subprocess.run(cmd, capture_output=True, text=True, input=config,
                           timeout=self.timeout + 10)
        if r.returncode != 0:
            raise RuntimeError(f"curl failed: {r.stderr[:200]}")
        return json.loads(r.stdout)

    def _post(self, url: str, headers: dict, body: dict) -> dict:
        if self._use_curl:
            return self._curl_post(url, headers, body)
        r = httpx.post(url, headers=headers, json=body, timeout=self.timeout)
        if r.status_code != 200:
            return {"_http_error": f"HTTP {r.status_code}: {r.text[:200]}"}
        return r.json()

    # -- Anthropic native format ----------------------------------------------

    def _call_anthropic(self, messages, system=None, max_tokens=512):
        url = self.base_url
        if url.endswith("/v1"):
            url = url[:-3]
        url += "/v1/messages"

        body = {"model": self.model, "max_tokens": max_tokens, "messages": messages}
        if system:
            body["system"] = system
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        data = self._post(url, headers, body)
        if "_http_error" in data:
            return {"error": data["_http_error"]}
        text = data.get("content", [{}])[0].get("text", "")
        usage = data.get("usage", {})
        return {
            "text": text,
            "input_tokens": usage.get("input_tokens", 0),
            "output_tokens": usage.get("output_tokens", 0),
            "raw": data,
        }

    # -- OpenAI compatible format ---------------------------------------------

    def _call_openai(self, messages, system=None, max_tokens=512):
        url = self.base_url
        if not url.endswith("/v1"):
            url += "/v1"
        url += "/chat/completions"

        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.extend(messages)
        body = {"model": self.model, "max_tokens": max_tokens, "messages": msgs}
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "content-type": "application/json",
        }

        data = self._post(url, headers, body)
        if "_http_error" in data:
            return {"error": data["_http_error"]}
        choice = data.get("choices", [{}])[0]
        text = choice.get("message", {}).get("content", "")
        usage = data.get("usage", {})
        return {
            "text": text,
            "input_tokens": usage.get("prompt_tokens", 0),
            "output_tokens": usage.get("completion_tokens", 0),
            "raw": data,
        }

    # -- Public API -----------------------------------------------------------

    def call(self, messages, system=None, max_tokens=512):
        """Send a chat completion request, auto-detecting format on first call.

        The method records wall-clock elapsed time and attaches it as the
        ``"time"`` key in the returned dict.

        Args:
            messages: List of message dicts, e.g.
                ``[{"role": "user", "content": "Hi"}]``.
            system: Optional system prompt string. Sent as a top-level
                ``"system"`` field (Anthropic) or as a system-role message
                (OpenAI).
            max_tokens: Maximum tokens to generate. Defaults to 512.

        Returns:
            A dict with the following keys on success:

            - ``text`` (str): The model's reply text.
            - ``input_tokens`` (int): Prompt token count.
            - ``output_tokens`` (int): Completion token count.
            - ``raw`` (dict): Full JSON response from the relay.
            - ``time`` (float): Wall-clock seconds elapsed.

            On failure the dict contains ``"error"`` (str) and ``"time"``.

        Examples:
            >>> client = APIClient("https://relay.example.com", "sk-...", "claude-3")
            >>> result = client.call([{"role": "user", "content": "Say hello"}])
            >>> if "error" not in result:
            ...     print(result["text"])
        """
        start = time.time()
        try:
            result = self._call_with_detection(messages, system, max_tokens)
            result["time"] = time.time() - start
            return result
        except Exception as e:
            return {"error": str(e), "time": time.time() - start}

    def _call_with_detection(self, messages, system, max_tokens):
        # Already detected — use that format
        if self._format == "openai":
            return self._call_openai(messages, system, max_tokens)
        if self._format == "anthropic":
            return self._call_anthropic(messages, system, max_tokens)

        # Auto-detect: try Anthropic first
        anthropic_result = None
        try:
            anthropic_result = self._call_anthropic(messages, system, max_tokens)
            if "error" not in anthropic_result and anthropic_result.get("text", "").strip():
                self._format = "anthropic"
                self._log("  [format] -> Anthropic native")
                return anthropic_result
        except Exception as e:
            if self._handle_ssl_error(e):
                # Retry Anthropic with curl before falling through to OpenAI
                try:
                    anthropic_result = self._call_anthropic(messages, system, max_tokens)
                    if "error" not in anthropic_result and anthropic_result.get("text", "").strip():
                        self._format = "anthropic"
                        self._log("  [format] -> Anthropic native (curl)")
                        return anthropic_result
                except Exception:
                    pass  # Fall through to OpenAI probe

        # Fallback to OpenAI
        self._log("  [format] Anthropic failed/empty, trying OpenAI...")
        openai_result = None
        try:
            openai_result = self._call_openai(messages, system, max_tokens)
            if "error" not in openai_result and openai_result.get("text", "").strip():
                self._format = "openai"
                suffix = " (curl)" if self._use_curl else ""
                self._log(f"  [format] -> OpenAI compatible{suffix}")
                return openai_result
        except Exception as e:
            if self._handle_ssl_error(e):
                return self._call_with_detection(messages, system, max_tokens)

        # Both failed — return whichever has more info
        if anthropic_result and "error" not in anthropic_result:
            self._format = "anthropic"
            return anthropic_result
        if openai_result and "error" not in openai_result:
            self._format = "openai"
            return openai_result
        return anthropic_result or openai_result or {"error": "Both formats failed"}

    def _handle_ssl_error(self, e: Exception) -> bool:
        """Switch to curl on SSL errors. Returns True if retry is warranted."""
        if not self._use_curl and ("SSL" in str(e) or "Connect" in type(e).__name__):
            self._use_curl = True
            self._log("  [transport] Python SSL error, switching to curl")
            return True
        return False

    def get_models(self):
        """Fetch the model list from the ``/v1/models`` endpoint.

        Uses the same transport (httpx or curl) that has been selected for
        regular requests.

        Returns:
            A list of model dicts as returned by the relay's ``data`` field,
            or an empty list if the request fails.

        Examples:
            >>> models = client.get_models()
            >>> for m in models:
            ...     print(m.get("id"))
        """
        url = self.base_url
        if not url.endswith("/v1"):
            url += "/v1"
        url += "/models"

        # Try both auth styles: OpenAI Bearer first, then Anthropic x-api-key
        auth_variants = [
            {"Authorization": f"Bearer {self.api_key}"},
            {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
        ]
        # If format already detected, try the matching auth first
        if self._format == "anthropic":
            auth_variants.reverse()

        for headers in auth_variants:
            try:
                if self._use_curl:
                    cmd = ["curl", "-sk", url, "--max-time", "15", "--config", "-"]
                    config = "\n".join(f'header = "{k}: {v}"' for k, v in headers.items())
                    r = subprocess.run(cmd, capture_output=True, text=True, input=config, timeout=25)
                    if r.returncode == 0:
                        data = json.loads(r.stdout).get("data", [])
                        if data:
                            return data
                else:
                    r = httpx.get(url, headers=headers, timeout=15)
                    if r.status_code == 200:
                        data = r.json().get("data", [])
                        if data:
                            return data
            except Exception:
                continue
        return []

    # -- Raw request (Step 9 error-leakage probes) ----------------------------

    def raw_request(self, method: str, path: str, headers: dict,
                    body: bytes, content_type: str = "application/json",
                    timeout: int = 30) -> dict:
        """Low-level request that preserves the full response body and headers.

        Bypasses the normal ``_post`` HTTP-status-code error handling so the
        Step 9 error-leakage probes can inspect error responses verbatim.
        Never raises; on transport failure, returns a dict with
        ``status == 0`` and an ``error`` string.

        Args:
            method: HTTP method (e.g. ``"POST"``).
            path: URL path starting with ``/``. If ``self.base_url`` already
                ends in ``/v1`` and ``path`` starts with ``/v1``, the duplicate
                segment is stripped.
            headers: Request headers (content-type is overridden by
                ``content_type``).
            body: Raw request body bytes.
            content_type: Content-Type header value. Defaults to
                ``"application/json"``.
            timeout: Per-request timeout in seconds. Defaults to 30.

        Returns:
            ``{"status": int, "headers": dict, "body": str, "error": str|None}``.
            ``status == 0`` indicates a transport failure; ``error`` is then
            a short diagnostic string.
        """
        base = self.base_url
        if base.endswith("/v1") and path.startswith("/v1"):
            base = base[:-3]
        url = base + path

        if self._use_curl:
            return self._curl_raw_request(method, url, headers, body, content_type, timeout)
        try:
            r = httpx.request(
                method=method,
                url=url,
                headers={**headers, "content-type": content_type},
                content=body,
                timeout=timeout,
            )
            return {
                "status": r.status_code,
                "headers": dict(r.headers),
                "body": r.text,
                "error": None,
            }
        except Exception as e:
            # On an SSL / connect error, transparently fall back to curl so
            # the audit can still inspect the relay's error surface even
            # under a self-signed certificate.
            if self._handle_ssl_error(e):
                return self._curl_raw_request(method, url, headers, body, content_type, timeout)
            return {"status": 0, "headers": {}, "body": "", "error": str(e)}

    def _curl_raw_request(self, method: str, url: str, headers: dict,
                          body: bytes, content_type: str, timeout: int) -> dict:
        """Curl-based fallback for ``raw_request``.

        Uses ``curl -sk -i -X <method>`` to capture both headers and body
        on stdout. Ignores self-signed certificate errors (``-k``).
        """
        all_headers = {**headers, "content-type": content_type}
        cmd = ["curl", "-sk", "-i", "-X", method, url,
               "--max-time", str(timeout), "--data-binary", "@-"]
        for k, v in all_headers.items():
            cmd.extend(["-H", f"{k}: {v}"])
        try:
            r = subprocess.run(cmd, capture_output=True, input=body,
                               timeout=timeout + 10)
            if r.returncode != 0:
                err = r.stderr.decode("utf-8", errors="replace")[:200]
                return {"status": 0, "headers": {}, "body": "",
                        "error": f"curl failed: {err}"}
            output = r.stdout.decode("utf-8", errors="replace")
            return _parse_curl_i_output(output)
        except Exception as e:
            return {"status": 0, "headers": {}, "body": "", "error": str(e)}

    # -- Streaming (Step 10 stream integrity) --------------------------------

    def stream_call(self, messages, system=None, max_tokens=512,
                    with_thinking: bool = True, timeout: int = 120) -> StreamSignals:
        """Open an Anthropic-format streaming request and capture SSE signals.

        Unlike :meth:`call`, this method is **Anthropic-only**. The SSE event
        schema differs from OpenAI's, and Step 10's whitelist is specifically
        about Anthropic's event shape. If the target relay is a pure
        OpenAI-compatible endpoint, the stream request returns a non-200
        status (or an OpenAI-format stream that fails our whitelist), and
        the caller should treat the result as *inconclusive*.

        Never raises. All transport errors are written to
        :attr:`StreamSignals.transport_error` so the caller can always
        inspect the returned dataclass. A zero-event return with
        ``transport_error is None`` is valid and means the relay opened the
        stream cleanly but produced no data.

        Args:
            messages: List of user/assistant message dicts.
            system: Optional system prompt string.
            max_tokens: Maximum tokens to generate. Defaults to 512.
            with_thinking: If True, include a ``thinking`` block in the
                request body to exercise the thinking-block delta path.
                Defaults to True because Step 10's whole point is to
                watch for thinking signature anomalies.
            timeout: Per-stream timeout in seconds. Defaults to 120.

        Returns:
            A fully populated :class:`StreamSignals` dataclass.
        """
        url = self.base_url
        if url.endswith("/v1"):
            url = url[:-3]
        url += "/v1/messages"

        body = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": messages,
            "stream": True,
        }
        if system:
            body["system"] = system
        if with_thinking:
            # thinking.budget_tokens must be strictly less than max_tokens
            body["thinking"] = {
                "type": "enabled",
                "budget_tokens": max(1, max_tokens - 1),
            }

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
            "accept": "text/event-stream",
        }

        signals = StreamSignals()
        start = time.time()
        try:
            if self._use_curl:
                self._stream_via_curl(url, headers, body, timeout, signals)
            else:
                self._stream_via_httpx(url, headers, body, timeout, signals)
        except Exception as e:
            if signals.transport_error is None:
                signals.transport_error = str(e)
        finally:
            signals.total_duration_seconds = time.time() - start

        return signals

    def _stream_via_httpx(self, url: str, headers: dict, body: dict,
                          timeout: int, signals: StreamSignals) -> None:
        """httpx branch of :meth:`stream_call`. SSL errors trigger a
        one-time fallback to the curl branch (mirroring :meth:`_post`)."""
        try:
            with httpx.Client(timeout=timeout) as client:
                with client.stream("POST", url, headers=headers, json=body) as response:
                    if response.status_code != 200:
                        # Read a tiny prefix of the error body for diagnostics,
                        # truncated so an unredacted error page cannot bloat signals.
                        try:
                            err_body = response.read().decode("utf-8", errors="ignore")[:200]
                        except Exception:
                            err_body = ""
                        signals.transport_error = (
                            f"HTTP {response.status_code}"
                            + (f": {err_body}" if err_body else "")
                        )
                        return
                    _parse_sse_stream(response.iter_bytes(), signals)
        except Exception as e:
            if self._handle_ssl_error(e):
                self._stream_via_curl(url, headers, body, timeout, signals)
                return
            raise

    def _stream_via_curl(self, url: str, headers: dict, body: dict,
                         timeout: int, signals: StreamSignals) -> None:
        """Curl branch of :meth:`stream_call`. Uses ``curl -N --no-buffer``
        to disable curl's own output buffering so SSE events are streamed
        to stdout as they arrive. The request body is piped via stdin."""
        cmd = [
            "curl", "-sk", "-N", "--no-buffer", "-X", "POST", url,
            "--max-time", str(timeout),
            "--data-binary", "@-",
        ]
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])

        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                proc.stdin.write(json.dumps(body).encode("utf-8"))
                proc.stdin.close()
            except (BrokenPipeError, OSError):
                # Curl already died (e.g. SSL handshake failed); let the
                # wait() + stderr read below report the real reason.
                pass

            def iter_stdout():
                while True:
                    chunk = proc.stdout.read(4096)
                    if not chunk:
                        break
                    yield chunk

            _parse_sse_stream(iter_stdout(), signals)
            proc.wait(timeout=timeout + 10)
            if proc.returncode != 0 and signals.raw_event_count == 0:
                err = proc.stderr.read().decode("utf-8", errors="replace")[:200]
                signals.transport_error = f"curl failed: {err}"
        except subprocess.TimeoutExpired:
            if signals.transport_error is None:
                signals.transport_error = "curl stream timeout"
            try:
                proc.kill()
            except Exception:
                pass
        except Exception as e:
            if signals.transport_error is None:
                signals.transport_error = str(e)
