#!/usr/bin/env python3
import argparse
import asyncio
import secrets
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, List
import sys

try:
	import httpx
except ImportError as exc:
	print("Error: httpx is required. Install it with 'pip install httpx'.", file=sys.stderr)
	sys.exit(1)

MIN_BLOB_SIZE = 46  # Matches server MIN_BLOB_SIZE requirement.


def percentile(sorted_values: List[float], pct: float) -> float:
	if not sorted_values:
		return float("nan")
	if pct <= 0:
		return sorted_values[0]
	if pct >= 100:
		return sorted_values[-1]
	k = (len(sorted_values) - 1) * (pct / 100.0)
	floor = int(k)
	ceil = min(floor + 1, len(sorted_values) - 1)
	if floor == ceil:
		return sorted_values[floor]
	weight = k - floor
	return sorted_values[floor] * (1.0 - weight) + sorted_values[ceil] * weight


@dataclass
class WorkerResult:
	successes: int = 0
	failures: int = 0
	post_latencies: List[float] = field(default_factory=list)
	get_latencies: List[float] = field(default_factory=list)
	roundtrip_latencies: List[float] = field(default_factory=list)
	verify_failures: int = 0
	error_samples: List[str] = field(default_factory=list)
	requests_made: int = 0


@dataclass
class PendingBlob:
	path: str
	payload: bytes
	start_time: float


async def worker(
	client: httpx.AsyncClient,
	path_prefix: str,
	payload_size: int,
	iterations: int,
	error_sample_limit: int,
	max_stored: int,
) -> WorkerResult:
	result = WorkerResult()
	if iterations <= 0:
		return result

	pending: Deque[PendingBlob] = deque()

	async def consume_pending_blob() -> None:
		if not pending:
			return
		blob = pending.popleft()
		start_get = time.perf_counter()
		try:
			result.requests_made += 1
			get_response = await client.get(blob.path)
		except Exception as exc:
			result.failures += 1
			if len(result.error_samples) < error_sample_limit:
				result.error_samples.append(f"GET {blob.path}: {exc!r}")
			return
		result.get_latencies.append(time.perf_counter() - start_get)
		roundtrip = time.perf_counter() - blob.start_time
		result.roundtrip_latencies.append(roundtrip)

		if get_response.status_code != httpx.codes.OK:
			result.failures += 1
			if len(result.error_samples) < error_sample_limit:
				result.error_samples.append(
					f"GET {blob.path}: unexpected status {get_response.status_code}"
				)
			return

		if get_response.content != blob.payload:
			result.failures += 1
			if len(result.error_samples) < error_sample_limit:
				result.error_samples.append(f"GET {blob.path}: payload mismatch")
			return

		try:
			result.requests_made += 1
			shadow_response = await client.get(blob.path)
		except Exception as exc:
			result.failures += 1
			result.verify_failures += 1
			if len(result.error_samples) < error_sample_limit:
				result.error_samples.append(f"VERIFY {blob.path}: {exc!r}")
			return
		if shadow_response.status_code != httpx.codes.NOT_FOUND:
			result.failures += 1
			result.verify_failures += 1
			if len(result.error_samples) < error_sample_limit:
				result.error_samples.append(
					f"VERIFY {blob.path}: expected 404, got {shadow_response.status_code}"
				)
			return

		result.successes += 1

	for i in range(iterations):
		payload = secrets.token_bytes(payload_size)
		blob_id = secrets.token_hex(16)
		relative_path = f"{path_prefix}{blob_id}"
		start_round = time.perf_counter()

		start_post = time.perf_counter()
		try:
			result.requests_made += 1
			post_response = await client.post(relative_path, content=payload)
		except Exception as exc:
			result.failures += 1
			if len(result.error_samples) < error_sample_limit:
				result.error_samples.append(f"POST {relative_path}: {exc!r}")
			continue
		result.post_latencies.append(time.perf_counter() - start_post)
		if post_response.status_code != httpx.codes.OK:
			result.failures += 1
			if len(result.error_samples) < error_sample_limit:
				result.error_samples.append(
					f"POST {relative_path}: unexpected status {post_response.status_code}"
				)
			continue
		pending.append(PendingBlob(relative_path, payload, start_round))

		while max_stored >= 0 and len(pending) > max_stored:
			await consume_pending_blob()

	while pending:
		await consume_pending_blob()

	return result


def format_latency_stats(values: List[float]) -> str:
	if not values:
		return "n/a"
	values_ms = [v * 1000.0 for v in values]
	values_ms.sort()
	avg = sum(values_ms) / len(values_ms)
	p50 = percentile(values_ms, 50)
	p90 = percentile(values_ms, 90)
	p99 = percentile(values_ms, 99)
	return f"avg {avg:.2f} ms | p50 {p50:.2f} ms | p90 {p90:.2f} ms | p99 {p99:.2f} ms"


async def run_benchmark(args: argparse.Namespace) -> None:
	total_roundtrips = args.requests
	concurrency = args.concurrency
	if total_roundtrips <= 0:
		raise ValueError("requests must be > 0")
	if concurrency <= 0:
		raise ValueError("concurrency must be > 0")
	if args.payload_size < MIN_BLOB_SIZE:
		raise ValueError(f"payload-size must be >= {MIN_BLOB_SIZE}")
	if args.stored < 0:
		raise ValueError("stored must be >= 0")

	base_url = args.url.rstrip("/")
	path_prefix = args.path_prefix
	if not path_prefix.startswith("/"):
		path_prefix = "/" + path_prefix
	if not path_prefix.endswith("/"):
		path_prefix += "/"

	timeout = httpx.Timeout(args.timeout, connect=args.timeout)
	limits = httpx.Limits(max_connections=concurrency * 4, max_keepalive_connections=concurrency * 2)

	async with httpx.AsyncClient(
		base_url=base_url,
		timeout=timeout,
		verify=not args.insecure,
		follow_redirects=False,
		limits=limits,
	) as client:
		quotient, remainder = divmod(total_roundtrips, concurrency)
		iterations = [quotient + (1 if i < remainder else 0) for i in range(concurrency)]
		stored_base, stored_remainder = divmod(args.stored, concurrency)
		stored_limits = [
			stored_base + (1 if i < stored_remainder else 0) for i in range(concurrency)
		]
		start = time.perf_counter()
		results = await asyncio.gather(
			*(worker(
				client,
				path_prefix,
				args.payload_size,
				iterations[i],
				args.error_samples,
				stored_limits[i],
			) for i in range(concurrency))
		)
		elapsed = time.perf_counter() - start

	total_successes = sum(r.successes for r in results)
	total_failures = sum(r.failures for r in results)
	total_verify_failures = sum(r.verify_failures for r in results)
	post_latencies: List[float] = []
	get_latencies: List[float] = []
	roundtrip_latencies: List[float] = []
	error_messages: List[str] = []
	for r in results:
		post_latencies.extend(r.post_latencies)
		get_latencies.extend(r.get_latencies)
		roundtrip_latencies.extend(r.roundtrip_latencies)
		error_messages.extend(r.error_samples)
	total_requests = sum(r.requests_made for r in results)

	print("Benchmark results")
	print(f"  target            : {base_url}{path_prefix}<id>")
	print(f"  concurrency       : {concurrency}")
	print(f"  payload size      : {args.payload_size} bytes")
	print(f"  attempted blobs   : {total_roundtrips}")
	print(f"  completed blobs   : {total_successes}")
	print(f"  failed attempts   : {total_failures}")
	print(f"  verify failures   : {total_verify_failures}")
	print(f"  target stored     : {args.stored}")
	print(f"  wall time         : {elapsed:.2f} s")
	if elapsed > 0:
		print(f"  blobs / second    : {total_successes / elapsed:.2f}")
		print(f"  reqs / second     : {total_requests / elapsed:.2f}")
	print(f"  POST latency      : {format_latency_stats(post_latencies)}")
	print(f"  GET latency       : {format_latency_stats(get_latencies)}")
	print(f"  roundtrip latency : {format_latency_stats(roundtrip_latencies)}")

	if error_messages:
		print("  sample errors:")
		for msg in error_messages[: args.error_samples]:
			print(f"    - {msg}")


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="Benchmark throughput and correctness of the /blob API."
	)
	parser.add_argument(
		"--url",
		default="http://127.0.0.1:8443",
		help="Base server URL (default: %(default)s)",
	)
	parser.add_argument(
		"--path-prefix",
		default="/blob/",
		help="Path prefix for blob endpoints (default: %(default)s)",
	)
	parser.add_argument(
		"--requests",
		type=int,
		default=512,
		help="Number of POST+GET round-trips to attempt (default: %(default)s)",
	)
	parser.add_argument(
		"--concurrency",
		type=int,
		default=16,
		help="Number of concurrent workers (default: %(default)s)",
	)
	parser.add_argument(
		"--payload-size",
		type=int,
		default=512,
		help=f"Payload size in bytes (min {MIN_BLOB_SIZE}, default: %(default)s)",
	)
	parser.add_argument(
		"--timeout",
		type=float,
		default=5.0,
		help="Per-request timeout in seconds (default: %(default)s)",
	)
	parser.add_argument(
		"--insecure",
		action="store_true",
		help="Disable TLS certificate verification",
	)
	parser.add_argument(
		"--error-samples",
		type=int,
		default=10,
		help="Maximum number of error samples to print (default: %(default)s)",
	)
	parser.add_argument(
		"--stored",
		type=int,
		default=0,
		help="Number of blobs to keep stored before fetching (default: %(default)s)",
	)
	return parser.parse_args()


def main() -> None:
	args = parse_args()
	try:
		asyncio.run(run_benchmark(args))
	except KeyboardInterrupt:
		print("Interrupted", flush=True)


if __name__ == "__main__":
	main()
