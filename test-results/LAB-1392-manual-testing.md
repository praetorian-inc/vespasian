# LAB-1392 Manual Testing Plan

## Prerequisites

- A SOAP/WSDL service running locally (e.g., DVWS at `http://localhost:80/dvwsuserservice`)
- A REST API running locally (e.g., any JSON API)

## Test 1: SOAP endpoint scan detects WSDL and generates WSDL output

```bash
vespasian scan http://localhost:80/dvwsuserservice -o scan-soap.yaml -v --probe --timeout=3m --max-pages=50
```

**Expected output** (stderr):
```
crawling http://localhost:80/dvwsuserservice (depth=3, max-pages=50, timeout=3m0s)
http://localhost:80/dvwsuserservice
captured N requests
detected API type: wsdl
generating WSDL spec
classified N API requests (threshold=0.50)
```

**Expected**: Output file contains WSDL XML with `<definitions>` root element.
**Before fix**: Would say "generating REST spec" and classify 0 requests.

## Test 2: WSDL URL scan detects WSDL

```bash
vespasian scan "http://localhost:80/dvwsuserservice?wsdl" -o scan-wsdl.yaml -v --probe --timeout=3m --max-pages=50
```

**Expected**: Same as Test 1 - detects WSDL type and generates WSDL output.

## Test 3: REST endpoint scan still works (regression check)

```bash
vespasian scan http://localhost:80/api -o scan-rest.yaml -v --probe --timeout=3m --max-pages=50
```

**Expected output** (stderr):
```
detected API type: rest
generating REST spec
```

**Expected**: Output file contains OpenAPI YAML spec. Behavior unchanged from before.

## Test 4: `generate wsdl` still works (regression check)

```bash
vespasian generate wsdl capture.json -o gen-wsdl.yaml -v
```

**Expected**: WSDL output generated correctly. No change from before.

## Automated Test Coverage

The following unit/integration tests cover the fix:

| Test | What it verifies |
|------|-----------------|
| `TestDetectAPIType/empty_requests_defaults_to_rest` | No traffic defaults to REST |
| `TestDetectAPIType/REST_JSON_requests_returns_rest` | JSON API traffic -> REST |
| `TestDetectAPIType/SOAP_request_with_SOAPAction_header_returns_wsdl` | SOAPAction header -> WSDL |
| `TestDetectAPIType/WSDL_URL_query_param_returns_wsdl` | `?wsdl` URL -> WSDL |
| `TestDetectAPIType/SOAP_envelope_in_body_returns_wsdl` | SOAP envelope body -> WSDL |
| `TestDetectAPIType/mixed_traffic_with_SOAP_present_returns_wsdl` | Mixed REST+SOAP -> WSDL |
| `TestDetectAPIType/SOAP_below_threshold_returns_rest` | Low-confidence SOAP -> REST |
| `TestGenerateSpec_WSDLType` | Full WSDL generation pipeline |
| `TestScanPipeline_WSDLDetection` | End-to-end scan pipeline regression for LAB-1392 |
