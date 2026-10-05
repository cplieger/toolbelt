# The REST handler

This page lists the routes `toolbelt/httpapi` serves, what each returns, and how it handles caching. It is for a developer exposing the engine to a web UI or to another process.

## Mounting it

`httpapi.Handler(engine, prefix)` returns an `http.Handler` with one route per engine call. Mount it at the prefix and at the prefix with a trailing slash:

```go
h := httpapi.Handler(engine, "/api/tools")
mux.Handle("/api/tools", h)
mux.Handle("/api/tools/", h)
```

The handler has no authentication and adds no middleware except its own cache policy. Wrap it in your own stack, such as an origin check or a gate that accepts only loopback connections. It speaks JSON in both directions and caps a request body at 64 KiB.

## Routes

| Route | Engine call | Notes |
| --- | --- | --- |
| `GET {prefix}` | `Inventory` | |
| `GET {prefix}/search?q=` | `SearchWithCounts` | Add `&unavailable=1` to include tools the catalog cannot install, with the reason. See below |
| `POST {prefix}` | `Add` | 202 `{job}`, with a null job for a template |
| `PATCH {prefix}/{name}` | `Patch` | Enables or disables a tool. 409 `has_dependents` with the names |
| `POST {prefix}/{name}/install` | `Install` | 409 `disabled` on a template |
| `POST {prefix}/update` | `Update` | Optional `{"names": [...]}` body |
| `DELETE {prefix}/{name}?force=1` | `Remove` or `RemoveWithDependents` | 202 `{job, dependents}`. 409 without `force`. 409 `essential` whatever `force` says |
| `GET {prefix}/jobs` | `Jobs` | The active job carries its output tail. A cancelled job carries `cancel_cause`. A job a GitHub rate limit failed carries `error_code` and `rate_limit` |
| `POST {prefix}/jobs/{id}/cancel` | `CancelJob` | The job reports `cancel_cause: caller` |
| `GET {prefix}/catalog` | `CatalogInfo` | Where the live catalog came from and how fresh it is |
| `POST {prefix}/catalog/refresh` | `RefreshCatalog` | 202 `{job}`. 409 `not_configured` without `Config.Refresh` |

`PATCH` takes `disabled` and `force` in the body. `DELETE` takes `force` in the query. A cascade that includes an essential tool is refused whole.

Search results leave out each entry's embedded install definition. In the reply, `truncated` is true when a block was cut to its limit, and `matched` is how many rows the query found before the cut. `apt_state` is `unavailable`, `indexing` or `available`, and `apt_available` gives the same answer as a bool.

## Replies and refusals

A change returns `202 {"job": ...}`, with a null job when nothing needed doing. A refusal is `409` with a coded error:

- `has_dependents` names the enabled tools that need this one.
- `essential` marks a tool your product declares it needs.
- `disabled` marks an install sent to a template.
- `not_configured` marks a catalog refresh on an engine without `Config.Refresh`.

A request that a GitHub rate limit stops before any job starts gets a `503` reply with the code `github_rate_limited`. That happens, for example, when `POST {prefix}` looks up the latest version. A job that fails for the same reason carries `error_code: github_rate_limited`. Both carry a `rate_limit` object:

```json
{"reset_at": 1791192600000, "limit": 60, "authenticated": false}
```

`reset_at` is in Unix milliseconds. For a limit on bursts of requests that names no time, it is one minute after the refusal. `limit` is the hourly limit, left out when GitHub did not send it. `authenticated` is false when the request carried no token. `secondary` is true when GitHub refused under its limit on bursts of requests rather than its hourly limit. `authenticated` is false when the request carried no token. `secondary` is true when GitHub refused under its limit on bursts of requests rather than its hourly limit.

To follow job progress, use the `Config` callbacks or poll `GET {prefix}/jobs`.

## Cache policy

Every response carries `Cache-Control: no-store`, including success bodies, rejected requests, engine errors, and the router's own 404, 405 and redirect replies. You need no no-store middleware of your own.

A `Cache-Control` your stack already set on the response is left as it is, the same rule `webhttp.JSONHeaders` applies to `X-Content-Type-Options`. A stricter policy such as `no-store, no-cache, must-revalidate`, or a weaker one on purpose, stays yours to set.
