# Web socket secrets provider

This library enables an easy setup for a secret provider trough wsock. This secrets provider was developed to be used with a [vFunction](https://developer.verifiably.com/docs/vfunctions/what-is-a-vfunction).

## Installation
To install this library run:

```
pip install verifiably_wsock_secrets_provider
```

## Setup
To create the server, just provide your secrets and start the communication trough wsock.

```python
from verifiably_wsock_secrets_provider import credentials_provider

credentials = {
    "account1":{
        "accountId": "1234",
        "token": "0000"
    }
}


expected_pcrs = {
    "0":"0000"
}

secretProvider = credentials_provider.SecretsProvider(credentials, expected_pcrs)

secretProvider.start()
```
