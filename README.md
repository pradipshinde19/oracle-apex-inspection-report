# Oracle APEX Inspection Report

A quality inspection report application built with Oracle APEX. The
application supports product selection, inspection detail entry,
checklist verification, review of inspection records, and inspection
reporting and analytics.

## Overview

The **Oracle APEX Inspection Report** project demonstrates how Oracle
APEX can be used to create a structured inspection workflow with
database-backed records and a dashboard-oriented interface.

### Key capabilities

-   User sign-in
-   Company and division context selection
-   Product selection for inspection
-   Inspection record listing
-   Inspection detail entry
-   Checklist point verification
-   Inspection record review
-   Inspection report summary
-   Inspection analytics and dashboard views

> Feature descriptions should reflect the behavior implemented in the
> exported application. Adjust this list if a feature is not included in
> your build.


## Technology Stack

-   **Oracle APEX** --- application development
-   **Oracle Database** --- relational data storage
-   **SQL** --- queries and data manipulation
-   **PL/SQL** --- database-side processing
-   **HTML, CSS, and JavaScript** --- included where used for UI
    customization or client-side behavior
-   **Git and GitHub** --- version control and project hosting

Confirm the exact Oracle APEX and Oracle Database versions in your
environment and add them here if useful.

## Requirements

Before importing the application, prepare:

-   An Oracle Database instance supported by your Oracle APEX version
-   An Oracle APEX workspace
-   A parsing schema with the privileges required by the application
-   The APEX application export and any required database object scripts

## Setup and Import

### 1. Clone the repository

``` bash
git clone https://github.com/pradipshinde19/oracle-apex-inspection-report.git
cd oracle-apex-inspection-report
```

### 2. Prepare database objects

1.  Review the SQL scripts supplied in the repository.
2.  Connect to the intended development schema.
3.  Create required tables, constraints, indexes, sequences, triggers,
    packages, and other dependencies in the order required by the
    application.
4.  Load sample data only if sample-data scripts are provided.

Do not run placeholder filenames from the example repository layout. Use
the actual scripts committed to the repository.

### 3. Import the APEX application

1.  Sign in to the Oracle APEX workspace.
2.  Open **App Builder** and select **Import**.
3.  Choose the application export SQL file.
4.  Follow the import wizard and select the appropriate parsing schema.
5.  Complete the import.

### 4. Configure and test

1.  Review authentication and authorization settings.
2.  Configure any required application items, substitutions,
    credentials, and environment-specific settings.
3.  Confirm that required database objects are valid.
4.  Test the workflow from login through product selection, inspection
    entry, checklist verification, review, and reporting.
5.  Verify dashboard totals against the underlying records.

The exact configuration depends on the application's authentication
scheme, database objects, and environment.

## Security and Data Privacy

-   Never commit passwords, tokens, private keys, or database connection
    secrets.
-   Do not publish real production records, personal information, or
    confidential company data.
-   Use fictional or sanitized data in public demonstrations.
-   Review application exports for embedded credentials,
    environment-specific URLs, and sensitive configuration before
    publishing.
-   Configure appropriate authentication, authorization, and database
    privileges before deploying the application.

## Development Notes

For reproducible setup, keep the application export and required
database scripts under version control. Document any manual
configuration that cannot be represented in the export, and update this
README whenever the setup steps or screenshots change.

## Author

**Pradip Shinde**

Oracle APEX Developer \| SQL \| PL/SQL \| Dashboard Development

-   GitHub: [@pradipshinde19](https://github.com/pradipshinde19)