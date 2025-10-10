import asyncio
import json
from datetime import datetime

import aio_pika


async def send_test_log():
    """Send a test log to RabbitMQ."""
    # Update with your credentials
    connection = await aio_pika.connect_robust(
        "amqp://guest:guest@localhost:5672/"
    )
    
    async with connection:
        channel = await connection.channel()
        
        # Declare the queue (must match your config)
        queue = await channel.declare_queue(
            "log_analysis_queue",  # Your queue name
            durable=True
        )
        
        # Create test log matching your expected format
        test_message = {
            "data": {
                "type": "application",
                "receiver": "log_analysis_service",
                "service_name": "test_service",
                "log_level": "INFO",
                "message": "This is a test log message",
                "timestamp": datetime.now().isoformat(),
                "metadata": {
                    "test": True,
                    "source": "test_script"
                }
            },
            "queue_name": "log_analysis_queue"
        }
        
        # Send message
        await channel.default_exchange.publish(
            aio_pika.Message(
                body=json.dumps(test_message).encode(),
                delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
                content_type="application/json",
            ),
            routing_key="log_analysis_queue"
        )
        
        print(f"✅ Test log sent successfully!")
        print(f"   Service: {test_message['data']['service_name']}")
        print(f"   Level: {test_message['data']['log_level']}")
        print(f"   Message: {test_message['data']['message']}")


if __name__ == "__main__":
    asyncio.run(send_test_log())