"""
ASM (Attack Surface Management) Alerts/Issues Example

This example demonstrates how to use the GTI SDK to:
- List ASM projects
- Search ASM issues with various filters
- Iterate through issues with pagination
- Process different entity types and severities
"""

from gti import (
    Client,
)


def safe_get_hits(response: dict) -> list:
    """Safely extract hits from ASM response.

    The ASM API can return:
    - {"success": true, "result": {"hits": [...]}}
    - {"success": false, "result": null}
    - {"success": true, "result": {"hits": []}}

    Args:
        response: API response dictionary.

    Returns:
        List of hits or empty list.
    """
    if not response:
        return []

    result = response.get("result")
    if result is None:
        return []

    return result.get("hits", [])


def safe_get_total(response: dict) -> int:
    """Safely extract total hits from ASM response.

    Args:
        response: API response dictionary.

    Returns:
        Total hits count or 0.
    """
    if not response:
        return 0

    result = response.get("result")
    if result is None:
        return 0

    return result.get("total_hits", 0)


def is_success(response: dict) -> bool:
    """Check if the response was successful with results.

    Args:
        response: API response dictionary.

    Returns:
        True if successful with non-null result.
    """
    if not response:
        return False

    if not response.get("success"):
        return False

    return response.get("result") is not None


def list_projects(client: Client):
    """List all ASM projects."""
    print("=" * 60)
    print("ASM Projects")
    print("=" * 60)

    response = client.asm_alerts.list_projects()

    if not response.get("success"):
        print("Failed to list projects")
        return

    projects = response.get("result", [])
    print(f"Found {len(projects)} project(s)\n")

    for project in projects:
        primary = " (PRIMARY)" if project.get("primary") else ""
        print(f"  Project: {project['name']}{primary}")
        print(f"    ID: {project['id']}")
        print(f"    UUID: {project['uuid']}")
        print(f"    Owner: {project.get('owner_email', 'N/A')}")
        print(f"    Organization: {project.get('organization_name', 'N/A')}")
        print(f"    Plan Status: {project.get('plan_status', 'N/A')}")
        print(f"    Created: {project.get('created_at', 'N/A')}")
        print()


def get_primary_project(client: Client) -> dict:
    """Get the primary project."""
    project = client.asm_alerts.get_primary_project()
    if project:
        print(f"Primary Project: {project['name']} ({project['uuid']})")
    else:
        print("No primary project found")
    return project


def search_basic(client: Client):
    """Basic search example."""
    print("\n" + "=" * 60)
    print("Basic Issue Search")
    print("=" * 60)

    # Search for high severity issues (severity 5 = critical)
    response = client.asm_alerts.search("severity:5", page_size=10)

    if not is_success(response):
        print(f"Search returned no results: {response.get('message', 'Unknown error')}")
        return

    hits = safe_get_hits(response)
    total = safe_get_total(response)

    print(f"Found {total} critical issues (showing {len(hits)})\n")

    for issue in hits[:5]:
        print(f"  Issue: {issue.get('pretty_name', issue.get('name'))}")
        print(f"    ID: {issue.get('id')}")
        print(f"    Severity: {issue.get('summary', {}).get('severity', 'N/A')}")
        print(f"    Status: {issue.get('summary', {}).get('status', 'N/A')}")
        print(f"    Entity: {issue.get('entity_type')} - {issue.get('entity_name')}")
        print(f"    Collection: {issue.get('collection', 'N/A')}")
        print(f"    First Seen: {issue.get('first_seen', 'N/A')}")
        print(f"    Last Seen: {issue.get('last_seen', 'N/A')}")
        print()


def iterate_issues(client: Client):
    """Iterate through issues with pagination."""
    print("\n" + "=" * 60)
    print("Iterating Through Issues")
    print("=" * 60)

    print("\n--- Iterating through critical issues ---")
    count = 0
    for issue in client.asm_alerts.iter_search(
        "severity:5",
        limit=20,
        page_size=10,
    ):
        count += 1
        if count <= 5:
            print(f"  {count}. {issue.get('pretty_name', issue.get('name'))[:50]}...")

    if count > 5:
        print(f"  ... Total: {count} issues")
    elif count == 0:
        print("  No critical issues found")
    else:
        print(f"  Total: {count} issues")

    print("\n--- Iterating through open high severity issues ---")
    count = 0
    for issue in client.asm_alerts.iter_search(
        "severity_gte:4 status_new:open",
        limit=50,
    ):
        count += 1

    print(f"  Found {count} open high severity issues")


def process_issue_details(client: Client):
    """Process and extract detailed issue information."""
    print("\n" + "=" * 60)
    print("Processing Issue Details")
    print("=" * 60)

    response = client.asm_alerts.search("severity_gte:3", page_size=3)
    hits = safe_get_hits(response)

    if not hits:
        print("No issues found with severity >= 3")
        return

    for issue in hits:
        print(f"\nIssue: {issue.get('pretty_name', issue.get('name'))}")
        print("-" * 50)

        # Basic info
        print(f"  ID: {issue.get('id')}")
        print(f"  UID: {issue.get('uid')}")
        print(f"  Name: {issue.get('name')}")

        # Summary info
        summary = issue.get("summary", {})
        print(f"\n  Summary:")
        print(f"    Severity: {summary.get('severity')}")
        print(f"    Status: {summary.get('status')}")
        print(f"    Status (New): {summary.get('status_new')}")
        print(f"    Status (Detailed): {summary.get('status_new_detailed')}")
        print(f"    Category: {summary.get('category')}")
        print(f"    Confidence: {summary.get('confidence')}")
        print(f"    Scoped: {summary.get('scoped')}")

        # Entity info
        print(f"\n  Entity:")
        print(f"    Type: {issue.get('entity_type')}")
        print(f"    Name: {issue.get('entity_name')}")
        print(f"    UID: {issue.get('entity_uid')}")

        # Collection info
        print(f"\n  Collection:")
        print(f"    Name: {issue.get('collection')}")
        print(f"    UUID: {issue.get('collection_uuid')}")
        print(f"    Type: {issue.get('collection_type')}")

        # Timestamps
        print(f"\n  Timestamps:")
        print(f"    First Seen: {issue.get('first_seen')}")
        print(f"    Last Seen: {issue.get('last_seen')}")

        # Tags
        tags = issue.get("tags", [])
        if tags:
            print(f"\n  Tags: {', '.join(tags)}")

        # Description
        description = issue.get("description")
        if description:
            desc_preview = (
                description[:200] + "..." if len(description) > 200 else description
            )
            print(f"\n  Description: {desc_preview}")


def search_with_project(client: Client):
    """Search issues within a specific project."""
    print("\n" + "=" * 60)
    print("Search with Project Filter")
    print("=" * 60)

    # Get primary project
    project = client.asm_alerts.get_primary_project()
    if not project:
        print("No primary project found")
        return

    project_id = project.get("uuid")
    print(f"Searching in project: {project.get('name')} ({project_id})\n")

    # Search within project
    response = client.asm_alerts.search(
        "severity_gte:3", page_size=5, project_id=project_id
    )

    hits = safe_get_hits(response)
    total = safe_get_total(response)
    print(f"Found {total} issues in project (showing {len(hits)})\n")

    for issue in hits[:3]:
        print(f"  • {issue.get('pretty_name', issue.get('name'))}")
        print(f"    Entity: {issue.get('entity_name')}")


def pagination_example(client: Client):
    """Manual pagination example."""
    print("\n" + "=" * 60)
    print("Manual Pagination")
    print("=" * 60)

    page = 1
    total_processed = 0
    page_token = None

    while page <= 3:  # Limit to 3 pages for demo
        response = client.asm_alerts.search(
            "severity_gte:3", page_size=10, page_token=page_token
        )

        if not is_success(response):
            print(f"Search returned no results on page {page}")
            break

        result = response.get("result", {})
        hits = result.get("hits", [])

        if not hits:
            print(f"No more issues on page {page}")
            break

        total_processed += len(hits)
        print(f"Page {page}: {len(hits)} issues (Total: {total_processed})")

        # Check if more pages available
        if not result.get("more"):
            print("No more pages")
            break

        page_token = result.get("next_page_token")
        if not page_token:
            print("No next page token")
            break

        page += 1

    print(f"\nProcessed {total_processed} issues across {page} page(s)")


def categorize_issues(client: Client):
    """Categorize issues by various attributes."""
    print("\n" + "=" * 60)
    print("Issue Categorization")
    print("=" * 60)

    # Get a sample of issues
    issues = list(client.asm_alerts.iter_search("severity_gte:1", limit=100))

    if not issues:
        print("No issues found")
        return

    print(f"Analyzing {len(issues)} issues...\n")

    # Categorize by severity
    severity_counts = {}
    for issue in issues:
        severity = issue.get("summary", {}).get("severity", "unknown")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    print("By Severity:")
    for severity in sorted(severity_counts.keys(), reverse=True):
        print(f"  Severity {severity}: {severity_counts[severity]} issues")

    # Categorize by status
    status_counts = {}
    for issue in issues:
        status = issue.get("summary", {}).get("status_new", "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1

    print("\nBy Status:")
    for status, count in sorted(status_counts.items()):
        print(f"  {status}: {count} issues")

    # Categorize by entity type
    entity_counts = {}
    for issue in issues:
        entity_type = issue.get("entity_type", "unknown")
        entity_counts[entity_type] = entity_counts.get(entity_type, 0) + 1

    print("\nBy Entity Type:")
    for entity_type, count in sorted(entity_counts.items(), key=lambda x: -x[1])[:10]:
        print(f"  {entity_type}: {count} issues")

    # Categorize by category
    category_counts = {}
    for issue in issues:
        category = issue.get("summary", {}).get("category", "unknown")
        category_counts[category] = category_counts.get(category, 0) + 1

    print("\nBy Category:")
    for category, count in sorted(category_counts.items(), key=lambda x: -x[1]):
        print(f"  {category}: {count} issues")


def main():
    """Main function demonstrating ASM alerts usage."""
    # Initialize client
    api_key = "api_key"

    print("GTI SDK - ASM Alerts Example")
    print("=" * 60)

    with Client(apikey=api_key) as client:
        try:
            # List projects
            list_projects(client)

            # Get primary project
            get_primary_project(client)

            # Search all severities first to see what's available

            # Basic search
            search_basic(client)

            # Search with filters
            search_with_filters(client)

            # High severity open issues
            search_high_severity_open(client)

            # Search by entity types
            search_by_entity_types(client)

            # Complex search
            complex_search(client)

            # Iterate through issues
            iterate_issues(client)

            # Process issue details
            process_issue_details(client)

            # Search with project
            search_with_project(client)

            # Pagination example
            pagination_example(client)

            # Categorize issues
            categorize_issues(client)

        except Exception as e:
            print(f"\nError: {e}")
            import traceback

            traceback.print_exc()


if __name__ == "__main__":
    main()
