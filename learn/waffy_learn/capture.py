"""
Traffic capture adapters.

Reads traffic from various sources and yields RequestSample objects
for the profiler.
"""

import json
import re
from pathlib import Path
from typing import Iterator
from urllib.parse import parse_qs, urlparse

from .profiler import RequestSample


class AccessLogCapture:
    """
    Parse nginx access logs with request body.

    Expected log_format (add to nginx.conf):

        log_format waffy_learn
            '$request_method $uri?$args '
            '$content_type '
            '$request_body';

    Or JSON log format (recommended):

        log_format waffy_learn_json escape=json
            '{"method":"$request_method",'
            '"uri":"$uri",'
            '"args":"$args",'
            '"content_type":"$content_type",'
            '"body":"$request_body",'
            '"headers":{"host":"$host","cookie":"$http_cookie"}}';
    """

    def __init__(self, log_path: Path, log_format: str = "json"):
        self.log_path = log_path
        self.log_format = log_format

    def read_samples(self) -> Iterator[RequestSample]:
        """Read and parse log entries into RequestSample objects."""
        with open(self.log_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    if self.log_format == "json":
                        yield from self._parse_json_line(line)
                    else:
                        yield from self._parse_text_line(line)
                except (json.JSONDecodeError, ValueError, KeyError):
                    continue  # Skip malformed lines

    def _parse_json_line(self, line: str) -> Iterator[RequestSample]:
        entry = json.loads(line)

        method = entry.get("method", "GET")
        uri = entry.get("uri", "/")
        args_str = entry.get("args", "")
        content_type = entry.get("content_type", "")
        body_str = entry.get("body", "")

        params: dict[str, str] = {}
        sources: dict[str, str] = {}

        # Parse query string
        if args_str and args_str != "-":
            for key, values in parse_qs(args_str).items():
                params[key] = values[0]  # Take first value
                sources[key] = "query"

        # Parse body based on content type
        if body_str and body_str != "-":
            body_params = self._parse_body(body_str, content_type)
            for key, value in body_params.items():
                params[key] = value
                sources[key] = "body"

        # Parse headers
        headers = entry.get("headers", {})
        for header_name, header_value in headers.items():
            if header_value and header_value != "-":
                h_key = header_name.title()
                params[h_key] = header_value
                sources[h_key] = "header"

        yield RequestSample(
            location=uri,
            method=method,
            params=params,
            param_sources=sources,
            content_type=content_type,
        )

    def _parse_text_line(self, line: str) -> Iterator[RequestSample]:
        # Basic text format: "METHOD /uri?args content_type body"
        parts = line.split(" ", 2)
        if len(parts) < 2:
            return

        method = parts[0]
        uri_full = parts[1]
        rest = parts[2] if len(parts) > 2 else ""

        parsed_url = urlparse(uri_full)
        uri = parsed_url.path
        args_str = parsed_url.query

        # Split rest into content_type and body
        rest_parts = rest.split(" ", 1)
        content_type = rest_parts[0] if rest_parts else ""
        body_str = rest_parts[1] if len(rest_parts) > 1 else ""

        params: dict[str, str] = {}
        sources: dict[str, str] = {}

        if args_str:
            for key, values in parse_qs(args_str).items():
                params[key] = values[0]
                sources[key] = "query"

        if body_str and body_str != "-":
            body_params = self._parse_body(body_str, content_type)
            for key, value in body_params.items():
                params[key] = value
                sources[key] = "body"

        yield RequestSample(
            location=uri,
            method=method,
            params=params,
            param_sources=sources,
            content_type=content_type,
        )

    def _parse_body(self, body: str, content_type: str) -> dict[str, str]:
        """Parse request body based on content type."""
        if "application/json" in content_type:
            return self._flatten_json(body)
        elif "x-www-form-urlencoded" in content_type:
            result = {}
            for key, values in parse_qs(body).items():
                result[key] = values[0]
            return result
        return {}

    def _flatten_json(self, body: str, prefix: str = "") -> dict[str, str]:
        """Flatten JSON object into dotpath key-value pairs."""
        try:
            data = json.loads(body) if isinstance(body, str) else body
        except json.JSONDecodeError:
            return {}

        result: dict[str, str] = {}

        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                if isinstance(value, (dict, list)):
                    result.update(self._flatten_json(value, full_key))
                else:
                    result[full_key] = str(value) if value is not None else ""
        elif isinstance(data, list):
            for i, item in enumerate(data):
                full_key = f"{prefix}.{i}" if prefix else str(i)
                if isinstance(item, (dict, list)):
                    result.update(self._flatten_json(item, full_key))
                else:
                    result[full_key] = str(item) if item is not None else ""

        return result


class HarCapture:
    """Parse HAR (HTTP Archive) files for bootstrapping profiles."""

    def __init__(self, har_path: Path):
        self.har_path = har_path

    def read_samples(self) -> Iterator[RequestSample]:
        with open(self.har_path) as f:
            har = json.load(f)

        for entry in har.get("log", {}).get("entries", []):
            request = entry.get("request", {})
            method = request.get("method", "GET")
            url = request.get("url", "")

            parsed = urlparse(url)
            uri = parsed.path
            content_type = ""

            params: dict[str, str] = {}
            sources: dict[str, str] = {}

            # Query string params
            for qs in request.get("queryString", []):
                params[qs["name"]] = qs.get("value", "")
                sources[qs["name"]] = "query"

            # Headers
            for header in request.get("headers", []):
                name = header["name"]
                if name.lower() == "content-type":
                    content_type = header.get("value", "")
                # Skip common uninteresting headers
                if name.lower() in ("host", "connection", "accept-encoding",
                                     "user-agent", "accept"):
                    continue
                params[name] = header.get("value", "")
                sources[name] = "header"

            # POST data
            post_data = request.get("postData", {})
            if post_data:
                mime = post_data.get("mimeType", "")
                for p in post_data.get("params", []):
                    params[p["name"]] = p.get("value", "")
                    sources[p["name"]] = "body"

                # If params list is empty, try parsing text
                if not post_data.get("params") and post_data.get("text"):
                    body_text = post_data["text"]
                    if "json" in mime:
                        bp = AccessLogCapture._flatten_json(None, body_text)
                        for k, v in bp.items():
                            params[k] = v
                            sources[k] = "body"

            yield RequestSample(
                location=uri,
                method=method,
                params=params,
                param_sources=sources,
                content_type=content_type,
            )
