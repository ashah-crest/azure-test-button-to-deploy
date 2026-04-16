"""
DTM (Digital Threat Monitoring) Alerts Example

This example demonstrates how to use the GTI SDK to:
- List DTM alerts with various filters
- Iterate through alerts with pagination
- Update alert status and tags
- Process different alert types (compromised credentials, etc.)
"""

from gti import (
    Client,
    AlertStatus,
    AlertType,
    AlertSeverity,
    AlertSortField,
    AlertSortOrder,
)


def list_alerts_basic(client: Client):
    """Basic example of listing alerts."""
    print("=" * 60)
    print("Basic Alert Listing")
    print("=" * 60)

    # Get the latest 10 alerts
    response = client.dtm_alerts.list(size=10)

    print(f"Retrieved {len(response.alerts)} alerts")
    print(f"Has more pages: {response.has_next}")

    for alert in response.alerts:
        print(f"\n  ID: {alert['id']}")
        print(f"  Title: {alert['title']}")
        print(f"  Type: {alert['alert_type']}")
        print(f"  Status: {alert['status']}")
        print(f"  Severity: {alert['severity']}")
        print(f"  Created: {alert['created_at']}")


def list_alerts_with_filters(client: Client):
    """Example of listing alerts with various filters."""
    print("\n" + "=" * 60)
    print("Filtered Alert Listing")
    print("=" * 60)

    # Get high severity alerts
    print("\n--- High Severity Alerts ---")
    response = client.dtm_alerts.list(
        severity=[AlertSeverity.HIGH],
        size=5,
    )
    print(f"Found {len(response.alerts)} high severity alerts")

    # Get new compromised credentials alerts
    print("\n--- New Compromised Credentials Alerts ---")
    response = client.dtm_alerts.list(
        status=[AlertStatus.NEW],
        alert_type=[AlertType.COMPROMISED_CREDENTIALS],
        size=5,
    )
    print(f"Found {len(response.alerts)} new credential alerts")

    # Get alerts from a specific date range
    print("\n--- Alerts from Date Range ---")
    response = client.dtm_alerts.list(
        since="2024-01-01T00:00:00Z",
        until="2024-12-31T23:59:59Z",
        sort=AlertSortField.CREATED_AT,
        order=AlertSortOrder.DESC,
        size=5,
    )
    print(f"Found {len(response.alerts)} alerts in date range")

    # Get alerts with minimum malware score
    print("\n--- Alerts with High Malware Score ---")
    response = client.dtm_alerts.list(
        mscore_gte=70,
        size=5,
    )
    print(f"Found {len(response.alerts)} alerts with mscore >= 70")


def paginate_alerts(client: Client):
    """Example of paginating through alerts."""
    print("\n" + "=" * 60)
    print("Alert Pagination")
    print("=" * 60)

    # Method 1: Manual pagination using next_page
    print("\n--- Manual Pagination ---")
    response = client.dtm_alerts.list(size=5)
    page_count = 1
    total_alerts = len(response.alerts)

    print(f"Page {page_count}: {len(response.alerts)} alerts")

    while response.has_next and page_count < 3:  # Limit to 3 pages for demo
        response = client.dtm_alerts.list(page=response.next_page)
        page_count += 1
        total_alerts += len(response.alerts)
        print(f"Page {page_count}: {len(response.alerts)} alerts")

    print(f"Total alerts across {page_count} pages: {total_alerts}")

    # Method 2: Using iterator (recommended)
    print("\n--- Using Iterator ---")
    count = 0
    for alert in client.dtm_alerts.iter(
        severity=[AlertSeverity.HIGH, AlertSeverity.MEDIUM],
        limit=20,  # Get max 20 alerts
        batch_size=10,  # Fetch 10 at a time
    ):
        count += 1
        if count <= 3:  # Only print first 3
            print(f"  {count}. {alert['title'][:50]}...")

    print(f"  ... Total: {count} alerts")


def process_compromised_credentials(client: Client):
    """Example of processing compromised credentials alerts."""
    print("\n" + "=" * 60)
    print("Processing Compromised Credentials")
    print("=" * 60)

    for alert in client.dtm_alerts.iter(
        alert_type=[AlertType.COMPROMISED_CREDENTIALS],
        status=[AlertStatus.NEW],
        limit=5,
    ):
        print(f"\nAlert: {alert['title']}")
        print(f"  ID: {alert['id']}")
        print(f"  Severity: {alert['severity']}")

        # Access the document containing credential details
        doc = alert.get("doc", {})

        # Extract service account information
        service_account = doc.get("service_account", {})
        if service_account:
            login = service_account.get("login", "N/A")
            service = service_account.get("service", {})
            service_name = service.get("name", "N/A")

            print(f"  Username: {login}")
            print(f"  Service: {service_name}")

            # Get URL if available
            inet_location = service.get("inet_location", {})
            if inet_location:
                print(f"  URL: {inet_location.get('url', 'N/A')}")

        # Extract source information
        source = doc.get("source", "N/A")
        source_url = doc.get("source_url", "N/A")
        print(f"  Source: {source}")
        print(f"  Source URL: {source_url}")

        # Extract file information if available
        source_file = doc.get("source_file", {})
        if source_file:
            print(f"  Source File: {source_file.get('filename', 'N/A')}")
            hashes = source_file.get("hashes", {})
            if hashes:
                print(f"  SHA256: {hashes.get('sha256', 'N/A')[:32]}...")

        # Extract topics/entities
        topics = alert.get("topics", [])
        domains = [t["value"] for t in topics if t.get("type") == "domain"]
        if domains:
            print(f"  Domains: {', '.join(domains[:3])}")


def process_alert_labels_and_topics(client: Client):
    """Example of processing alert labels and topics."""
    print("\n" + "=" * 60)
    print("Processing Labels and Topics")
    print("=" * 60)

    response = client.dtm_alerts.list(size=3)

    for alert in response.alerts:
        print(f"\nAlert: {alert['title'][:60]}...")

        # Process labels (threat classifications)
        labels = alert.get("labels", [])
        if labels:
            print("  Labels:")
            for label in labels[:3]:
                print(
                    f"    - {label.get('label', 'N/A')} "
                    f"(confidence: {label.get('confidence', 0)}%)"
                )

        # Process topics (extracted entities)
        topics = alert.get("topics", [])
        if topics:
            # Group topics by type
            topic_types = {}
            for topic in topics:
                topic_type = topic.get("type", "unknown")
                if topic_type not in topic_types:
                    topic_types[topic_type] = []
                topic_types[topic_type].append(topic.get("value", ""))

            print("  Topics:")
            for topic_type, values in list(topic_types.items())[:5]:
                print(f"    {topic_type}: {', '.join(values[:2])}")


def update_alert_status(client: Client):
    """Example of updating alert status and tags."""
    print("\n" + "=" * 60)
    print("Updating Alert Status")
    print("=" * 60)

    # Get a new alert to update
    response = client.dtm_alerts.list(
        status=[AlertStatus.NEW],
        size=1,
    )

    if not response.alerts:
        print("No new alerts to update")
        return

    alert = response.alerts[0]
    alert_id = alert["id"]
    print(f"Alert ID: {alert_id}")
    print(f"Current Status: {alert['status']}")

    # Example: Mark as read
    # updated = client.dtm_alerts.mark_as_read(alert_id)
    # print(f"Marked as read: {updated.get('status')}")

    # Example: Update status to in_progress
    # updated = client.dtm_alerts.update(
    #     alert_id,
    #     status=AlertStatus.IN_PROGRESS
    # )
    # print(f"Updated status: {updated.get('status')}")

    # Example: Add tags
    # updated = client.dtm_alerts.add_tags(
    #     alert_id,
    #     tags=["reviewed", "high-priority", "needs-investigation"]
    # )
    # print(f"Added tags: {updated.get('tags')}")

    # Example: Close with tags
    # updated = client.dtm_alerts.update(
    #     alert_id,
    #     status=AlertStatus.CLOSED,
    #     tags=["resolved", "false-positive"]
    # )

    print("\n(Update operations commented out to avoid modifying real data)")
    print("Uncomment the code above to actually update alerts")


def get_single_alert(client: Client):
    """Example of getting a single alert by ID."""
    print("\n" + "=" * 60)
    print("Get Single Alert")
    print("=" * 60)

    # First, get an alert ID from the list
    response = client.dtm_alerts.list(size=1)

    if not response.alerts:
        print("No alerts found")
        return

    alert_id = response.alerts[0]["id"]
    print(f"Fetching alert: {alert_id}")

    # Get full alert details
    alert = client.dtm_alerts.get(alert_id)

    print(f"\nAlert Details:")
    print(f"  ID: {alert.get('id')}")
    print(f"  Title: {alert.get('title')}")
    print(f"  Type: {alert.get('alert_type')}")
    print(f"  Status: {alert.get('status')}")
    print(f"  Severity: {alert.get('severity')}")
    print(f"  Created: {alert.get('created_at')}")
    print(f"  Updated: {alert.get('updated_at')}")
    print(f"  Monitor ID: {alert.get('monitor_id')}")
    print(f"  Has Analysis: {alert.get('has_analysis')}")

    # Print match information
    doc_matches = alert.get("doc_matches", [])
    if doc_matches:
        print(f"\n  Document Matches:")
        for match in doc_matches[:3]:
            print(f"    Path: {match.get('match_path')}")
            locations = match.get("locations", [])
            for loc in locations[:2]:
                print(f"      Value: {loc.get('value')}")


def search_alerts(client: Client):
    """Example of searching alerts with Lucene query."""
    print("\n" + "=" * 60)
    print("Searching Alerts")
    print("=" * 60)

    # Search for alerts containing specific terms
    # The search parameter uses Lucene query syntax
    response = client.dtm_alerts.list(
        search="credential OR password",
        size=5,
    )
    print(f"Found {len(response.alerts)} alerts matching 'credential OR password'")

    for alert in response.alerts[:3]:
        print(f"  - {alert['title'][:60]}...")

    # Search with base64 encoded query
    # import base64
    # encoded_query = base64.b64encode(b"malware").decode()
    # response = client.dtm_alerts.list(
    #     search=encoded_query,
    #     search_encoding="base64",
    #     size=5,
    # )


def filter_by_monitor(client: Client):
    """Example of filtering alerts by monitor ID."""
    print("\n" + "=" * 60)
    print("Filter by Monitor")
    print("=" * 60)

    # First, get a monitor ID from an existing alert
    response = client.dtm_alerts.list(size=1)

    if not response.alerts:
        print("No alerts found")
        return

    monitor_id = response.alerts[0].get("monitor_id")
    if not monitor_id:
        print("No monitor ID in alert")
        return

    print(f"Filtering by monitor: {monitor_id}")

    # Get alerts from specific monitor
    response = client.dtm_alerts.list(
        monitor_id=monitor_id,
        monitor_name=True,  # Include monitor name in response
        size=5,
    )

    print(f"Found {len(response.alerts)} alerts from this monitor")


def process_all_alert_types(client: Client):
    """Example of processing different alert types."""
    print("\n" + "=" * 60)
    print("Process All Alert Types")
    print("=" * 60)

    alert_types = [
        AlertType.COMPROMISED_CREDENTIALS,
        AlertType.DOMAIN_DISCOVERY,
        AlertType.FORUM_POST,
        AlertType.MESSAGE,
        AlertType.PASTE,
        AlertType.SHOP_LISTING,
        AlertType.TWEET,
        AlertType.WEB_CONTENT,
    ]

    for alert_type in alert_types:
        response = client.dtm_alerts.list(
            alert_type=[alert_type],
            size=1,
        )
        count = len(response.alerts)
        has_more = "+" if response.has_next else ""
        print(f"  {alert_type.value}: {count}{has_more} alerts")


def main():
    """Main function demonstrating DTM alerts usage."""
    # Initialize client
    # You can also use environment variable: GTI_API_KEY
    api_key = "api_key"

    print("GTI SDK - DTM Alerts Example")
    print("=" * 60)

    with Client(apikey=api_key) as client:
        try:
            # Basic listing
            list_alerts_basic(client)

            # Filtered listing
            list_alerts_with_filters(client)

            # Pagination examples
            paginate_alerts(client)

            # Process compromised credentials
            process_compromised_credentials(client)

            # Process labels and topics
            process_alert_labels_and_topics(client)

            # Get single alert
            get_single_alert(client)

            # Search alerts
            search_alerts(client)

            # Filter by monitor
            filter_by_monitor(client)

            # Process all alert types
            process_all_alert_types(client)

            # Update alert (commented out by default)
            update_alert_status(client)

        except Exception as e:
            print(f"\nError: {e}")
            raise


if __name__ == "__main__":
    main()
