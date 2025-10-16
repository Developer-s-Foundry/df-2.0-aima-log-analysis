#!/usr/bin/env python3
"""
Comprehensive Log Sender for Testing AIMA Log Analysis System

This script sends various types of logs to test:
1. Critical errors (should trigger alerts)
2. Patterns (should trigger recommendations)
3. Anomalies (should trigger alerts)
4. Normal logs (just stored)

Usage:
    python test_send_log.py --scenario all
    python test_send_log.py --scenario critical
    python test_send_log.py --scenario pattern
"""

import argparse
import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import aio_pika
from aio_pika import DeliveryMode, Message

from app.core.config import get_settings


class LogSender:
    """Sends test logs to RabbitMQ for the AIMA Log Analysis System."""

    def __init__(self, rabbitmq_url: str = None):
        if rabbitmq_url is None:
            settings = get_settings()
            self.rabbitmq_url = settings.rabbitmq_url
        else:
            self.rabbitmq_url = rabbitmq_url
        self.connection = None
        self.channel = None
        self.queue_name = "log_analysis_queue"

    async def connect(self):
        """Connect to RabbitMQ."""
        print(f"🔌 Connecting to RabbitMQ: {self.rabbitmq_url}")
        self.connection = await aio_pika.connect_robust(self.rabbitmq_url)
        self.channel = await self.connection.channel()

        # Declare the queue
        await self.channel.declare_queue(self.queue_name, durable=True)
        print(f"✅ Connected to queue: {self.queue_name}")

    async def close(self):
        """Close RabbitMQ connection."""
        if self.connection:
            await self.connection.close()
            print("🔌 Connection closed")

    async def send_log(self, log_data: Dict[str, Any]) -> None:
        """Send a single log to RabbitMQ."""
        message_body = {
            "data": log_data,
            "queue_name": self.queue_name,
        }

        message = Message(
            body=json.dumps(message_body).encode(),
            delivery_mode=DeliveryMode.PERSISTENT,
            content_type="application/json",
        )

        await self.channel.default_exchange.publish(
            message,
            routing_key=self.queue_name,
        )

        print(f"📤 Sent: [{log_data['log_level']}] {log_data['service_name']}: {log_data['message'][:50]}...")

    async def send_multiple_logs(self, logs: List[Dict[str, Any]], delay: float = 0.5):
        """Send multiple logs with delay between each."""
        for i, log in enumerate(logs, 1):
            await self.send_log(log)
            if i < len(logs):
                await asyncio.sleep(delay)

    # ========================================================================
    # TEST SCENARIOS
    # ========================================================================

    def get_critical_error_logs(self) -> List[Dict[str, Any]]:
        """Scenario 1: Critical errors that should trigger ALERTS."""
        print("\n🚨 Scenario 1: CRITICAL ERRORS (Should trigger alerts)")
        print("=" * 60)

        return [
            {
                "type": "log_entry",
                "receiver": "log_analysis_service",
                "service_name": "payment-service",
                "log_level": "CRITICAL",
                "message": "Database connection pool exhausted - all connections in use",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "raw_data": json.dumps({
                    "error_code": "DB_POOL_EXHAUSTED",
                    "pool_size": 20,
                    "active_connections": 20,
                    "waiting_requests": 45
                })
            },
            {
                "type": "log_entry",
                "receiver": "log_analysis_service",
                "service_name": "auth-service",
                "log_level": "FATAL",
                "message": "Redis connection failed - authentication service unavailable",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "raw_data": json.dumps({
                    "error_code": "REDIS_CONNECTION_FAILED",
                    "retry_attempts": 3,
                    "last_error": "Connection refused"
                })
            },
            {
                "type": "log_entry",
                "receiver": "log_analysis_service",
                "service_name": "order-service",
                "log_level": "CRITICAL",
                "message": "Memory usage critical: 95% - potential memory leak detected",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "raw_data": json.dumps({
                    "memory_usage_percent": 95,
                    "heap_size_mb": 1900,
                    "max_heap_mb": 2000
                })
            }
        ]

    def get_pattern_logs(self) -> List[Dict[str, Any]]:
        """Scenario 2: Recurring patterns that should trigger RECOMMENDATIONS."""
        print("\n💡 Scenario 2: RECURRING PATTERNS (Should trigger recommendations)")
        print("=" * 60)

        base_time = datetime.now(timezone.utc)
        logs = []

        # Pattern 1: Slow database queries (recurring issue)
        for i in range(5):
            logs.append({
                "type": "log_entry",
                "receiver": "log_analysis_service",
                "service_name": "product-service",
                "log_level": "WARNING",
                "message": f"Slow query detected: SELECT * FROM products WHERE category_id = {100 + i} (execution time: {2.5 + i * 0.3}s)",
                "timestamp": (base_time - timedelta(minutes=i * 2)).isoformat(),
                "raw_data": json.dumps({
                    "query_type": "SELECT",
                    "execution_time_ms": int((2500 + i * 300)),
                    "table": "products",
                    "rows_scanned": 50000 + i * 1000
                })
            })

        # Pattern 2: API timeout errors (recurring issue)
        for i in range(4):
            logs.append({
                "type": "log_entry",
                "receiver": "log_analysis_service",
                "service_name": "notification-service",
                "log_level": "ERROR",
                "message": f"External API timeout: Failed to send notification to user {1000 + i} after 30 seconds",
                "timestamp": (base_time - timedelta(minutes=i * 3)).isoformat(),
                "raw_data": json.dumps({
                    "api_endpoint": "https://api.sms-provider.com/send",
                    "timeout_seconds": 30,
                    "retry_count": 3
                })
            })

        return logs

    def get_anomaly_logs(self) -> List[Dict[str, Any]]:
        """Scenario 3: Anomalous behavior that should trigger ALERTS."""
        print("\n⚠️  Scenario 3: ANOMALIES (Should trigger alerts)")
        print("=" * 60)

        return [
            {
                "type": "log_entry",
                "receiver": "log_analysis_service",
                "service_name": "payment-service",
                "log_level": "ERROR",
                "message": "Unusual payment failure rate: 45% of transactions failed in last 5 minutes",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "raw_data": json.dumps({
                    "total_transactions": 200,
                    "failed_transactions": 90,
                    "failure_rate": 45.0,
                    "normal_failure_rate": 2.5
                })
            },
            {
                "type": "log_entry",
                "receiver": "log_analysis_service",
                "service_name": "user-service",
                "log_level": "WARNING",
                "message": "Spike in failed login attempts: 500 failed logins in 2 minutes from IP 192.168.1.100",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "raw_data": json.dumps({
                    "failed_attempts": 500,
                    "time_window_minutes": 2,
                    "source_ip": "192.168.1.100",
                    "normal_rate": 5
                })
            }
        ]

    def get_normal_logs(self) -> List[Dict[str, Any]]:
        """Scenario 4: Normal logs (just stored, no alerts/recommendations)."""
        print("\n✅ Scenario 4: NORMAL LOGS (Just stored)")
        print("=" * 60)

        return [
            {
                "type": "log_entry",
                "receiver": "log_analysis_service",
                "service_name": "api-gateway",
                "log_level": "INFO",
                "message": "Request processed successfully: GET /api/products - 200 OK (45ms)",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "raw_data": json.dumps({
                    "method": "GET",
                    "path": "/api/products",
                    "status_code": 200,
                    "response_time_ms": 45
                })
            },
            {
                "type": "log_entry",
                "receiver": "log_analysis_service",
                "service_name": "order-service",
                "log_level": "INFO",
                "message": "Order created successfully: order_id=ORD-12345, total=$99.99",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "raw_data": json.dumps({
                    "order_id": "ORD-12345",
                    "total_amount": 99.99,
                    "items_count": 3
                })
            },
            {
                "type": "log_entry",
                "receiver": "log_analysis_service",
                "service_name": "cache-service",
                "log_level": "DEBUG",
                "message": "Cache hit: key=user:1234, ttl=3600s",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "raw_data": json.dumps({
                    "cache_key": "user:1234",
                    "ttl_seconds": 3600,
                    "hit": True
                })
            }
        ]

    def get_mixed_scenario_logs(self) -> List[Dict[str, Any]]:
        """Scenario 5: Mixed logs (realistic production scenario)."""
        print("\n🎯 Scenario 5: MIXED REALISTIC SCENARIO")
        print("=" * 60)

        logs = []
        base_time = datetime.now(timezone.utc)

        # Simulate a production incident timeline

        # T-0: Normal operations
        logs.append({
            "type": "log_entry",
            "receiver": "log_analysis_service",
            "service_name": "payment-service",
            "log_level": "INFO",
            "message": "Payment processed successfully: transaction_id=TXN-001",
            "timestamp": (base_time - timedelta(minutes=10)).isoformat(),
        })

        # T-5: First warning signs
        logs.append({
            "type": "log_entry",
            "receiver": "log_analysis_service",
            "service_name": "payment-service",
            "log_level": "WARNING",
            "message": "Database query slow: 1.5s response time",
            "timestamp": (base_time - timedelta(minutes=5)).isoformat(),
        })

        # T-3: More warnings
        logs.append({
            "type": "log_entry",
            "receiver": "log_analysis_service",
            "service_name": "payment-service",
            "log_level": "WARNING",
            "message": "Database query slow: 2.8s response time",
            "timestamp": (base_time - timedelta(minutes=3)).isoformat(),
        })

        # T-2: Errors start
        logs.append({
            "type": "log_entry",
            "receiver": "log_analysis_service",
            "service_name": "payment-service",
            "log_level": "ERROR",
            "message": "Payment processing failed: Database timeout after 5 seconds",
            "timestamp": (base_time - timedelta(minutes=2)).isoformat(),
        })

        # T-1: Critical situation
        logs.append({
            "type": "log_entry",
            "receiver": "log_analysis_service",
            "service_name": "payment-service",
            "log_level": "CRITICAL",
            "message": "Database connection pool exhausted - service degraded",
            "timestamp": (base_time - timedelta(minutes=1)).isoformat(),
        })

        # T-0: Complete failure
        logs.append({
            "type": "log_entry",
            "receiver": "log_analysis_service",
            "service_name": "payment-service",
            "log_level": "FATAL",
            "message": "Payment service unavailable - all database connections failed",
            "timestamp": base_time.isoformat(),
        })

        return logs

    async def run_scenario(self, scenario: str):
        """Run a specific test scenario."""
        await self.connect()

        try:
            if scenario == "critical":
                logs = self.get_critical_error_logs()
            elif scenario == "pattern":
                logs = self.get_pattern_logs()
            elif scenario == "anomaly":
                logs = self.get_anomaly_logs()
            elif scenario == "normal":
                logs = self.get_normal_logs()
            elif scenario == "mixed":
                logs = self.get_mixed_scenario_logs()
            elif scenario == "all":
                print("\n🎯 Running ALL scenarios")
                print("=" * 60)

                await self.run_scenario("critical")
                await asyncio.sleep(2)

                await self.run_scenario("pattern")
                await asyncio.sleep(2)

                await self.run_scenario("anomaly")
                await asyncio.sleep(2)

                await self.run_scenario("normal")
                await asyncio.sleep(2)

                await self.run_scenario("mixed")

                print("\n" + "=" * 60)
                print("✅ All scenarios completed!")
                return
            else:
                print(f"❌ Unknown scenario: {scenario}")
                return

            print(f"\n📊 Sending {len(logs)} logs...")
            await self.send_multiple_logs(logs, delay=0.5)

            print(f"\n✅ Scenario '{scenario}' completed!")
            print("\n💡 Expected Results:")

            if scenario == "critical":
                print("  - 🚨 Should trigger ALERTS to Alert System (Team A)")
                print("  - 📧 Check alerts_queue for critical alerts")
            elif scenario == "pattern":
                print("  - 💡 Should trigger RECOMMENDATIONS to Recommendation System (Team E)")
                print("  - 📧 Check recommendation_queue for pattern insights")
            elif scenario == "anomaly":
                print("  - 🚨 Should trigger ALERTS due to anomalous behavior")
                print("  - 📧 Check alerts_queue for anomaly alerts")
            elif scenario == "normal":
                print("  - 📝 Logs stored in database only")
                print("  - ✅ No alerts or recommendations expected")
            elif scenario == "mixed":
                print("  - 🚨 Should trigger ALERTS for critical/fatal logs")
                print("  - 💡 Should trigger RECOMMENDATIONS for patterns")
                print("  - 📧 Check both queues")

        finally:
            await self.close()


async def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Send test logs to AIMA Log Analysis System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all scenarios
  python test_send_log.py --scenario all

  # Test critical errors only
  python test_send_log.py --scenario critical

  # Test pattern detection
  python test_send_log.py --scenario pattern

  # Test anomaly detection
  python test_send_log.py --scenario anomaly

  # Test normal logs
  python test_send_log.py --scenario normal

  # Test realistic mixed scenario
  python test_send_log.py --scenario mixed

Available scenarios:
  - critical: Critical errors (triggers alerts)
  - pattern:  Recurring patterns (triggers recommendations)
  - anomaly:  Anomalous behavior (triggers alerts)
  - normal:   Normal logs (just stored)
  - mixed:    Realistic production scenario
  - all:      Run all scenarios
        """
    )

    parser.add_argument(
        "--scenario",
        choices=["critical", "pattern", "anomaly", "normal", "mixed", "all"],
        default="all",
        help="Test scenario to run"
    )

    # Get default RabbitMQ URL from settings
    settings = get_settings()
    parser.add_argument(
        "--rabbitmq-url",
        default=settings.rabbitmq_url,
        help="RabbitMQ connection URL"
    )

    args = parser.parse_args()

    print("🚀 AIMA Log Analysis System - Comprehensive Test")
    print("=" * 60)
    print(f"Scenario: {args.scenario}")
    print(f"RabbitMQ: {args.rabbitmq_url}")
    print("=" * 60)

    sender = LogSender(args.rabbitmq_url)

    try:
        await sender.run_scenario(args.scenario)

        print("\n" + "=" * 60)
        print("🎉 Test completed successfully!")
        print("\n📋 Next Steps:")
        print("  1. Check application logs: docker compose logs log_analysis_service")
        print("  2. Check database: SELECT * FROM log_entries ORDER BY timestamp DESC LIMIT 10;")
        print("  3. Check alerts queue: docker compose exec rabbitmq rabbitmqctl list_queues")
        settings = get_settings()
        api_url = f"http://{settings.host}:{settings.port}"
        print(f"  4. View API: curl {api_url}/api/v1/logs")
        print(f"  5. Check AI status: curl -H 'Authorization: Bearer token' {api_url}/api/v1/ai/status")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    exit(asyncio.run(main()))
