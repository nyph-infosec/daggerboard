# DaggerBoard API Guide

## Endpoints

### `POST /api/login/`

Authenticates a user and returns a token.

#### Parameters
- `username`: The authorized user's username.
- `password`: The authorized user's password.

#### Response

The response is a JSON object containing the authentication token:

```json
{
    "token": "9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b"
}
```

### `POST /api/sbom/`

Processes an uploaded SBOM file.

#### Parameters

- `file`: The SBOM file to upload.

#### Response

A transaction ID that can be used to retrieve the DaggerBoardAPI object once processing is complete.

### `GET /api/sbom/{transaction_id}`

Returns the DaggerBoardAPI object with the given transaction ID. If the upload associated with the transaction ID is still running, the response will be `{"status": "Task is still processing"}`.

#### Parameters

- `transaction_id`: The ID of the DaggerBoardAPI object to retrieve.

#### Response

If the upload is complete, the response will be a JSON object representing the DaggerBoardAPI object with the following fields:

- `id`: The ID of the DaggerBoardAPI object.
- `documentname`: The name of the document.
- `vendorname`: The name of the vendor.
- `critical_risk_count`: The count of critical risks.
- `high_risk_count`: The count of high risks.
- `medium_risk_count`: The count of medium risks.
- `low_risk_count`: The count of low risks.
- `risk_grade`: The risk letter grade.
- `created_at`: The timestamp when the DaggerBoardAPI object was created.

Example response:

```json
{
    "id": 16,
    "documentname": "example-1.0.0",
    "vendorname": "Example Vendor",
    "critical_risk_count": 0,
    "high_risk_count": 9,
    "medium_risk_count": 21,
    "low_risk_count": 0,
    "risk_grade": "C",
    "created_at": "2022-12-01T10:30:15.123456-04:00"
}
```

### `GET /api/sbom/`

Returns a list of all DaggerBoardAPI objects.

#### Response

A list of DaggerBoardAPI objects.

Example response:

```json
[
    {
        "id": 1,
        "documentname": "ExampleDocument1",
        "vendorname": "ExampleVendor1",
        "critical_risk_count": 0,
        "high_risk_count": 0,
        "medium_risk_count": 3,
        "low_risk_count": 1,
        "risk_grade": "A",
        "created_at": "2022-12-01T10:30:15.123456-04:00"
    },
    {
        "id": 2,
        "documentname": "ExampleDocument2",
        "vendorname": "ExampleVendor2",
        "critical_risk_count": 2,
        "high_risk_count": 1,
        "medium_risk_count": 1,
        "low_risk_count": 0,
        "risk_grade": "C",
        "created_at": "2022-12-02T11:31:16.234567-04:00"
    },
    {
        "id": 3,
        "documentname": "ExampleDocument3",
        "vendorname": "ExampleVendor3",
        "critical_risk_count": 2,
        "high_risk_count": 9,
        "medium_risk_count": 2,
        "low_risk_count": 0,
        "risk_grade": "D",
        "created_at": "2022-12-03T12:32:17.345678-04:00"
    }
]
```


## Authentication

All endpoints require authentication via token. The token is provided in the `Authorization` header of the HTTP request in the format `Token <your-token>`.

Here is an example:

```http
GET /api/sbom/
Host: example.com
Authorization: Token 7db4ab4a6775eb767fd76aaea5d85a967624cabc
```

## Rate Limiting

The Daggerboard API uses a rate limiting policy to     limit the rate of API calls that may be made by a given user.

The default setting is currently at 100. If you need to modify this, please do so in the Django settings.

The user id will be used as a unique cache key if the user is authenticated.  For anonymous requests, the IP address of the request will be used.

## Throttling

Throttling is applied on a per-user basis.

## Filtering

The `GET /api/sbom/` endpoint supports filtering by `documentname` and `vendorname`.

## Ordering

The `GET /api/sbom/` endpoint supports ordering by `documentname` and `vendorname`.

## Grading Process

The grading process is based on a **weighted average calculation**. Each severity level (critical, high, medium, low) has a corresponding weight. The count of CVEs for each severity level is multiplied by its weight to get a weighted score.

The total score is the sum of these weighted scores. This total score is then divided by the total weight to get the final result.

This result is then compared to predefined grade thresholds to determine the final letter grade. The thresholds for each grade are defined and can be changed in the Grade Thresholds Settings.
