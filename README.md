# aktest-se

Developer-friendly & type-safe Python SDK specifically catered to leverage *aktest-se* API.

<div align="left">
    <a href="https://www.speakeasy.com/?utm_source=aktest-se&utm_campaign=python"><img src="https://custom-icon-badges.demolab.com/badge/-Built%20By%20Speakeasy-212015?style=for-the-badge&logoColor=FBE331&logo=speakeasy&labelColor=545454" /></a>
    <a href="https://opensource.org/licenses/MIT">
        <img src="https://img.shields.io/badge/License-MIT-blue.svg" style="width: 100px; height: 28px;" />
    </a>
</div>


<br /><br />
> [!IMPORTANT]
> This SDK is not yet ready for production use. To complete setup please follow the steps outlined in your [workspace](https://app.speakeasy.com/org/akamai/gss). Delete this section before > publishing to a package manager.

<!-- Start Summary [summary] -->
## Summary

For more information about the API: [See documentation for Akamai's Certificate Provisioning System API](https://techdocs.akamai.com/cps/reference)
<!-- End Summary [summary] -->

<!-- Start Table of Contents [toc] -->
## Table of Contents

* [SDK Installation](#sdk-installation)
* [IDE Support](#ide-support)
* [SDK Example Usage](#sdk-example-usage)
* [Available Resources and Operations](#available-resources-and-operations)
* [Retries](#retries)
* [Error Handling](#error-handling)
* [Server Selection](#server-selection)
* [Custom HTTP Client](#custom-http-client)
* [Debugging](#debugging)
<!-- End Table of Contents [toc] -->

<!-- Start SDK Installation [installation] -->
## SDK Installation

The SDK can be installed with either *pip* or *poetry* package managers.

### PIP

*PIP* is the default package installer for Python, enabling easy installation and management of packages from PyPI via the command line.

```bash
pip install git+<UNSET>.git
```

### Poetry

*Poetry* is a modern tool that simplifies dependency management and package publishing by using a single `pyproject.toml` file to handle project metadata and dependencies.

```bash
poetry add git+<UNSET>.git
```
<!-- End SDK Installation [installation] -->

<!-- Start IDE Support [idesupport] -->
## IDE Support

### PyCharm

Generally, the SDK will work well with most IDEs out of the box. However, when using PyCharm, you can enjoy much better integration with Pydantic by installing an additional plugin.

- [PyCharm Pydantic Plugin](https://docs.pydantic.dev/latest/integrations/pycharm/)
<!-- End IDE Support [idesupport] -->

<!-- Start SDK Example Usage [usage] -->
## SDK Example Usage

### Example

```python
# Synchronous Example
from aktest_se import Se

s = Se()

res = s.certificates.get_active_certificates(contract_id="K-0N7RAK7", account_switch_key="1-5C0YLB:1-8BYUX")

if res is not None:
    # handle response
    pass
```

</br>

The same SDK client can also be used to make asychronous requests by importing asyncio.
```python
# Asynchronous Example
from aktest_se import Se
import asyncio

async def main():
    s = Se()
    res = await s.certificates.get_active_certificates_async(contract_id="K-0N7RAK7", account_switch_key="1-5C0YLB:1-8BYUX")
    if res is not None:
        # handle response
        pass

asyncio.run(main())
```
<!-- End SDK Example Usage [usage] -->

<!-- Start Available Resources and Operations [operations] -->
## Available Resources and Operations

<details open>
<summary>Available methods</summary>

### [certificates](docs/sdks/certificates/README.md)

* [get_active_certificates](docs/sdks/certificates/README.md#get_active_certificates) - List active certificates

### [changes](docs/sdks/changes/README.md)

* [get_enrollment_change](docs/sdks/changes/README.md#get_enrollment_change) - Get change status
* [delete_enrollment_change](docs/sdks/changes/README.md#delete_enrollment_change) - Cancel a change
* [get_change_deployment_schedule](docs/sdks/changes/README.md#get_change_deployment_schedule) - Get a deployment schedule
* [get_change_allowed_input_param](docs/sdks/changes/README.md#get_change_allowed_input_param) - Get a change
* [post_change_allowed_input_param](docs/sdks/changes/README.md#post_change_allowed_input_param) - Update a change
* [get_history_changes](docs/sdks/changes/README.md#get_history_changes) - Get change history

### [deployments](docs/sdks/deployments/README.md)

* [put_change_deployment_schedule](docs/sdks/deployments/README.md#put_change_deployment_schedule) - Update a deployment schedule
* [get_deployments](docs/sdks/deployments/README.md#get_deployments) - List deployments
* [get_deployments_production](docs/sdks/deployments/README.md#get_deployments_production) - Get production deployment
* [get_deployment_staging](docs/sdks/deployments/README.md#get_deployment_staging) - Get staging deployment

### [enrollments](docs/sdks/enrollments/README.md)

* [post_enrollment](docs/sdks/enrollments/README.md#post_enrollment) - Create an enrollment
* [get_enrollments](docs/sdks/enrollments/README.md#get_enrollments) - List enrollments
* [get_enrollment](docs/sdks/enrollments/README.md#get_enrollment) - Get an enrollment
* [put_enrollment](docs/sdks/enrollments/README.md#put_enrollment) - Update an enrollment
* [delete_enrollment](docs/sdks/enrollments/README.md#delete_enrollment) - Remove an enrollment
* [get_dv_history](docs/sdks/enrollments/README.md#get_dv_history) - Get DV history
* [get_history_certificates](docs/sdks/enrollments/README.md#get_history_certificates) - Get certificate history


</details>
<!-- End Available Resources and Operations [operations] -->

<!-- Start Retries [retries] -->
## Retries

Some of the endpoints in this SDK support retries. If you use the SDK without any configuration, it will fall back to the default retry strategy provided by the API. However, the default retry strategy can be overridden on a per-operation basis, or across the entire SDK.

To change the default retry strategy for a single API call, simply provide a `RetryConfig` object to the call:
```python
from aktest_se import Se
from se.utils import BackoffStrategy, RetryConfig

s = Se()

res = s.certificates.get_active_certificates(contract_id="K-0N7RAK7", account_switch_key="1-5C0YLB:1-8BYUX",
    RetryConfig("backoff", BackoffStrategy(1, 50, 1.1, 100), False))

if res is not None:
    # handle response
    pass

```

If you'd like to override the default retry strategy for all operations that support retries, you can use the `retry_config` optional parameter when initializing the SDK:
```python
from aktest_se import Se
from se.utils import BackoffStrategy, RetryConfig

s = Se(
    retry_config=RetryConfig("backoff", BackoffStrategy(1, 50, 1.1, 100), False),
)

res = s.certificates.get_active_certificates(contract_id="K-0N7RAK7", account_switch_key="1-5C0YLB:1-8BYUX")

if res is not None:
    # handle response
    pass

```
<!-- End Retries [retries] -->

<!-- Start Error Handling [errors] -->
## Error Handling

Handling errors in this SDK should largely match your expectations. All operations return a response object or raise an exception.

By default, an API error will raise a models.SDKError exception, which has the following properties:

| Property        | Type             | Description           |
|-----------------|------------------|-----------------------|
| `.status_code`  | *int*            | The HTTP status code  |
| `.message`      | *str*            | The error message     |
| `.raw_response` | *httpx.Response* | The raw HTTP response |
| `.body`         | *str*            | The response content  |

When custom error responses are specified for an operation, the SDK may also raise their associated exceptions. You can refer to respective *Errors* tables in SDK docs for more details on possible exception types for each operation. For example, the `get_active_certificates_async` method may raise the following exceptions:

| Error Type      | Status Code     | Content Type    |
| --------------- | --------------- | --------------- |
| models.SDKError | 4XX, 5XX        | \*/\*           |

### Example

```python
from aktest_se import Se, models

s = Se()

res = None
try:
    res = s.certificates.get_active_certificates(contract_id="K-0N7RAK7", account_switch_key="1-5C0YLB:1-8BYUX")

    if res is not None:
        # handle response
        pass

except models.SDKError as e:
    # handle exception
    raise(e)
```
<!-- End Error Handling [errors] -->

<!-- Start Server Selection [server] -->
## Server Selection

### Select Server by Index

You can override the default server globally by passing a server index to the `server_idx: int` optional parameter when initializing the SDK client instance. The selected server will then be used as the default on the operations that use it. This table lists the indexes associated with the available servers:

| # | Server | Variables |
| - | ------ | --------- |
| 0 | `https://{hostname}/cps/v2` | None |

#### Example

```python
from aktest_se import Se

s = Se(
    server_idx=0,
)

res = s.certificates.get_active_certificates(contract_id="K-0N7RAK7", account_switch_key="1-5C0YLB:1-8BYUX")

if res is not None:
    # handle response
    pass

```


### Override Server URL Per-Client

The default server can also be overridden globally by passing a URL to the `server_url: str` optional parameter when initializing the SDK client instance. For example:
```python
from aktest_se import Se

s = Se(
    server_url="https://{hostname}/cps/v2",
)

res = s.certificates.get_active_certificates(contract_id="K-0N7RAK7", account_switch_key="1-5C0YLB:1-8BYUX")

if res is not None:
    # handle response
    pass

```
<!-- End Server Selection [server] -->

<!-- Start Custom HTTP Client [http-client] -->
## Custom HTTP Client

The Python SDK makes API calls using the [httpx](https://www.python-httpx.org/) HTTP library.  In order to provide a convenient way to configure timeouts, cookies, proxies, custom headers, and other low-level configuration, you can initialize the SDK client with your own HTTP client instance.
Depending on whether you are using the sync or async version of the SDK, you can pass an instance of `HttpClient` or `AsyncHttpClient` respectively, which are Protocol's ensuring that the client has the necessary methods to make API calls.
This allows you to wrap the client with your own custom logic, such as adding custom headers, logging, or error handling, or you can just pass an instance of `httpx.Client` or `httpx.AsyncClient` directly.

For example, you could specify a header for every request that this sdk makes as follows:
```python
from aktest_se import Se
import httpx

http_client = httpx.Client(headers={"x-custom-header": "someValue"})
s = Se(client=http_client)
```

or you could wrap the client with your own custom logic:
```python
from aktest_se import Se
from aktest_se.httpclient import AsyncHttpClient
import httpx

class CustomClient(AsyncHttpClient):
    client: AsyncHttpClient

    def __init__(self, client: AsyncHttpClient):
        self.client = client

    async def send(
        self,
        request: httpx.Request,
        *,
        stream: bool = False,
        auth: Union[
            httpx._types.AuthTypes, httpx._client.UseClientDefault, None
        ] = httpx.USE_CLIENT_DEFAULT,
        follow_redirects: Union[
            bool, httpx._client.UseClientDefault
        ] = httpx.USE_CLIENT_DEFAULT,
    ) -> httpx.Response:
        request.headers["Client-Level-Header"] = "added by client"

        return await self.client.send(
            request, stream=stream, auth=auth, follow_redirects=follow_redirects
        )

    def build_request(
        self,
        method: str,
        url: httpx._types.URLTypes,
        *,
        content: Optional[httpx._types.RequestContent] = None,
        data: Optional[httpx._types.RequestData] = None,
        files: Optional[httpx._types.RequestFiles] = None,
        json: Optional[Any] = None,
        params: Optional[httpx._types.QueryParamTypes] = None,
        headers: Optional[httpx._types.HeaderTypes] = None,
        cookies: Optional[httpx._types.CookieTypes] = None,
        timeout: Union[
            httpx._types.TimeoutTypes, httpx._client.UseClientDefault
        ] = httpx.USE_CLIENT_DEFAULT,
        extensions: Optional[httpx._types.RequestExtensions] = None,
    ) -> httpx.Request:
        return self.client.build_request(
            method,
            url,
            content=content,
            data=data,
            files=files,
            json=json,
            params=params,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
            extensions=extensions,
        )

s = Se(async_client=CustomClient(httpx.AsyncClient()))
```
<!-- End Custom HTTP Client [http-client] -->

<!-- Start Debugging [debug] -->
## Debugging

You can setup your SDK to emit debug logs for SDK requests and responses.

You can pass your own logger class directly into your SDK.
```python
from aktest_se import Se
import logging

logging.basicConfig(level=logging.DEBUG)
s = Se(debug_logger=logging.getLogger("aktest_se"))
```

You can also enable a default debug logger by setting an environment variable `SE_DEBUG` to true.
<!-- End Debugging [debug] -->

<!-- Placeholder for Future Speakeasy SDK Sections -->

# Development

## Maturity

This SDK is in beta, and there may be breaking changes between versions without a major version update. Therefore, we recommend pinning usage
to a specific package version. This way, you can install the same version each time without breaking changes unless you are intentionally
looking for the latest version.

## Contributions

While we value open-source contributions to this SDK, this library is generated programmatically. Any manual changes added to internal files will be overwritten on the next generation. 
We look forward to hearing your feedback. Feel free to open a PR or an issue with a proof of concept and we'll do our best to include it in a future release. 

### SDK Created by [Speakeasy](https://www.speakeasy.com/?utm_source=aktest-se&utm_campaign=python)
